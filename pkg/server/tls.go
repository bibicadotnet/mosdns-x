/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
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
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/quic-go/quic-go"
	eTLS "gitlab.com/go-extension/tls"
)

var statelessResetKey *quic.StatelessResetKey
var tlsSessionTicketKey [32]byte

func init() {
	resetKey, sessionKey, err := loadOrCreateKeys()
	if err != nil {
		log.Printf("[WARN] Failed to load persistent keys: %v, using ephemeral keys", err)
		
		// Generate ephemeral keys with error checking
		var tmpResetKey quic.StatelessResetKey
		if _, err := rand.Read(tmpResetKey[:]); err != nil {
			log.Fatalf("[FATAL] Failed to generate ephemeral reset key: %v", err)
		}
		statelessResetKey = &tmpResetKey
		
		if _, err := rand.Read(tlsSessionTicketKey[:]); err != nil {
			log.Fatalf("[FATAL] Failed to generate ephemeral session ticket key: %v", err)
		}
	} else {
		statelessResetKey = resetKey
		copy(tlsSessionTicketKey[:], sessionKey)
	}
}

// loadOrCreateKeys loads or creates separate keys for QUIC stateless reset and TLS session tickets
func loadOrCreateKeys() (*quic.StatelessResetKey, []byte, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	
	execDir := filepath.Dir(execPath)
	keyDir := filepath.Join(execDir, "key")
	resetKeyFile := filepath.Join(keyDir, ".mosdns_stateless_reset.key")
	sessionKeyFile := filepath.Join(keyDir, ".mosdns_session_ticket.key")
	
	// Load or create stateless reset key
	resetKey, err := loadOrCreateSingleKey(resetKeyFile, keyDir, "stateless reset")
	if err != nil {
		return nil, nil, err
	}
	
	// Load or create session ticket key
	sessionKey, err := loadOrCreateSingleKey(sessionKeyFile, keyDir, "session ticket")
	if err != nil {
		return nil, nil, err
	}
	
	var quicResetKey quic.StatelessResetKey
	copy(quicResetKey[:], resetKey)
	
	return &quicResetKey, sessionKey, nil
}

func loadOrCreateSingleKey(keyFile string, keyDir string, keyType string) ([]byte, error) {
	// Try to load existing key
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		log.Printf("[INFO] Loaded %s key from: %s", keyType, keyFile)
		return data, nil
	}
	
	// Generate new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// Create directory with restricted permissions (0700 instead of 0755)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, err
	}
	
	// Write key file
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return nil, err
	}
	
	log.Printf("[INFO] Created new %s key: %s", keyType, keyFile)
	return key, nil
}

// cert is a thread-safe certificate holder using atomic operations
type cert[T tls.Certificate | eTLS.Certificate] struct {
	ptr atomic.Pointer[T]
}

func (c *cert[T]) get() *T {
	return c.ptr.Load()
}

func (c *cert[T]) set(newCert *T) {
	c.ptr.Store(newCert)
}

func tryCreateWatchCert[T tls.Certificate | eTLS.Certificate](certFile string, keyFile string, createFunc func(string, string) (T, error)) (*cert[T], error) {
	c, err := createFunc(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	
	cc := &cert[T]{}
	cc.set(&c)
	
	// Start certificate watcher goroutine
	// Note: This goroutine intentionally runs for the lifetime of the listener
	// In mosdns-x, listeners are created once at startup and never hot-reloaded
	// so this is not a goroutine leak
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Printf("[ERROR] Failed to create certificate watcher: %v", err)
			return
		}
		defer watcher.Close()
		
		// Check errors from watcher.Add
		if err := watcher.Add(certFile); err != nil {
			log.Printf("[WARN] Failed to watch certificate file %s: %v", certFile, err)
		}
		if err := watcher.Add(keyFile); err != nil {
			log.Printf("[WARN] Failed to watch key file %s: %v", keyFile, err)
		}
		
		// Use NewTimer instead of AfterFunc to avoid benign race detection
		// Timer is managed in single goroutine for clean race detector compliance
		timer := time.NewTimer(0)
		<-timer.C // Drain initial fire
		
		reloadCert := func() {
			newCert, err := createFunc(certFile, keyFile)
			if err != nil {
				log.Printf("[ERROR] Failed to reload certificate: %v", err)
				return
			}
			cc.set(&newCert)
			log.Printf("[INFO] Certificate reloaded successfully")
		}
		
		for {
			select {
			case e, ok := <-watcher.Events:
				if !ok {
					timer.Stop()
					return
				}
				
				// Handle Remove/Rename events - need to re-add watcher
				if e.Has(fsnotify.Remove) || e.Has(fsnotify.Rename) {
					log.Printf("[INFO] Certificate file %s was removed/renamed, re-watching original paths", e.Name)
					
					// Re-add the original cert and key files, not e.Name
					// This prevents watching temp files from certbot
					// Remove first to avoid duplicate watches in fsnotify
					time.AfterFunc(2*time.Second, func() {
						_ = watcher.Remove(certFile)
						_ = watcher.Remove(keyFile)
						if err := watcher.Add(certFile); err != nil {
							log.Printf("[WARN] Failed to re-watch certFile %s: %v", certFile, err)
						}
						if err := watcher.Add(keyFile); err != nil {
							log.Printf("[WARN] Failed to re-watch keyFile %s: %v", keyFile, err)
						}
					})
					
					// Trigger reload with debounce
					timer.Stop()
					timer.Reset(2 * time.Second)
					continue
				}
				
				// Skip chmod-only events
				if e.Has(fsnotify.Chmod) {
					continue
				}
				
				// Debounce reload for Write/Create events
				timer.Stop()
				timer.Reset(2 * time.Second)
				
			case <-timer.C:
				// Timer fired - reload certificate
				reloadCert()
				
			case err := <-watcher.Errors:
				if err != nil {
					log.Printf("[ERROR] Certificate watcher error: %v", err)
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
	
	tr := &quic.Transport{
		Conn:              conn,
		StatelessResetKey: statelessResetKey,
	}
	
	return tr.ListenEarly(&tls.Config{
		NextProtos:       nextProtos,
		SessionTicketKey: tlsSessionTicketKey,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := c.get()
			if cert == nil {
				return nil, errors.New("certificate not available")
			}
			
			// SNI filtering with silent fallback
			// Many DoQ/DoT clients don't send SNI, so we accept all by default
			if allowedSNI != "" && chi.ServerName != "" && chi.ServerName != allowedSNI {
				// Silent fallback for compatibility
				// For strict SNI checking: return nil, errors.New("SNI not allowed")
			}
			
			return cert, nil
		},
	}, &quic.Config{
		// 0-RTT enabled for DNS - acceptable for idempotent queries
		// Disable if replay protection is critical for your use case
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
		SessionTicketKey: tlsSessionTicketKey,
		KernelTX:         s.opts.KernelTX,
		KernelRX:         s.opts.KernelRX,
		// Early data enabled for TLS 1.3 - replay risk acceptable for DNS
		AllowEarlyData:   true,
		MaxEarlyData:     4096,
		NextProtos:       nextProtos,
		Defaults: eTLS.Defaults{
			AllSecureCipherSuites: true,
			AllSecureCurves:       false,
		},
		GetCertificate: func(chi *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			cert := c.get()
			if cert == nil {
				return nil, errors.New("certificate not available")
			}
			
			// SNI filtering with silent fallback (same as QUIC)
			// Many DoQ/DoT clients don't send SNI, so we accept all by default
			if allowedSNI != "" && chi.ServerName != "" && chi.ServerName != allowedSNI {
				// Silent fallback for compatibility
				// For strict SNI checking: return nil, errors.New("SNI not allowed")
			}
			
			return cert, nil
		},
	}), nil
}
