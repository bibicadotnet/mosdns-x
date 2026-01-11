/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/quic-go/quic-go"
	eTLS "gitlab.com/go-extension/tls"
)

var statelessResetKey []byte

func init() {
	var err error
	statelessResetKey, err = loadOrCreateKey()
	if err != nil {
		log.Printf("[WARN] Failed to load stateless reset key: %v, using ephemeral key", err)
		statelessResetKey = make([]byte, 32)
		rand.Read(statelessResetKey)
	}
}

func loadOrCreateKey() ([]byte, error) {
	execPath, _ := os.Executable()
	keyFile := filepath.Join(filepath.Dir(execPath), ".mosdns_stateless_reset.key")
	
	// Try read existing key
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		log.Printf("[INFO] Loaded stateless reset key from: %s", keyFile)
		return data, nil
	}
	
	// Create new random key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	
	// Save to file
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return nil, err
	}
	
	log.Printf("[INFO] Created new stateless reset key: %s", keyFile)
	return key, nil
}

type cert[T tls.Certificate | eTLS.Certificate] struct {
	c *T
}

func tryCreateWatchCert[T tls.Certificate | eTLS.Certificate](certFile string, keyFile string, createFunc func(string, string) (T, error)) (*cert[T], error) {
	c, err := createFunc(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cc := &cert[T]{&c}
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		defer watcher.Close()
		_ = watcher.Add(certFile)
		_ = watcher.Add(keyFile)
		var timer *time.Timer
		for {
			select {
			case e, ok := <-watcher.Events:
				if !ok {
					if timer != nil {
						timer.Stop()
						timer = nil
					}
					return
				}
				if e.Has(fsnotify.Chmod) || e.Has(fsnotify.Remove) {
					continue
				}
				if timer == nil {
					timer = time.AfterFunc(time.Second, func() {
						timer = nil
						if c, err := createFunc(certFile, keyFile); err == nil {
							cc.c = &c
						}
					})
				} else {
					timer.Reset(time.Second)
				}
			case err := <-watcher.Errors:
				if err != nil && timer != nil {
					timer.Stop()
					timer = nil
				}
			}
		}
	}()
	return cc, nil
}

func (s *Server) CreateQUICListner(conn net.PacketConn, nextProtos []string, allowedSNI string) (*quic.EarlyListener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}
	c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair)
	if err != nil {
		return nil, err
	}
	return quic.ListenEarly(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if allowedSNI != "" && chi.ServerName != allowedSNI {
				return nil, errors.New("invalid sni")
			}
			return c.c, nil
		},
	}, &quic.Config{
		StatelessResetKey:              statelessResetKey,
		Allow0RTT:                      true,
		InitialStreamReceiveWindow:     1252,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024,
	})
}

func (s *Server) CreateETLSListner(l net.Listener, nextProtos []string, allowedSNI string) (net.Listener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}
	c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, eTLS.LoadX509KeyPair)
	if err != nil {
		return nil, err
	}
	return eTLS.NewListener(l, &eTLS.Config{
		KernelTX:       s.opts.KernelTX,
		KernelRX:       s.opts.KernelRX,
		AllowEarlyData: true,
		MaxEarlyData:   4096,
		NextProtos:     nextProtos,
		Defaults: eTLS.Defaults{
			AllSecureCipherSuites: true,
			AllSecureCurves:       true,
		},
		GetCertificate: func(chi *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			if allowedSNI != "" && chi.ServerName != allowedSNI {
				return nil, errors.New("invalid sni")
			}
			return c.c, nil
		},
	}), nil
}
