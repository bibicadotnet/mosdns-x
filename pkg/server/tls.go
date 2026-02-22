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
	"go.uber.org/zap"
)

var statelessResetKey *quic.StatelessResetKey
var tlsSessionTicketKey [32]byte

func init() {
	resetKey, sessionKey, err := loadOrCreateKeys()
	if err != nil {
		log.Printf("[WARN] Failed to load persistent keys: %v, using ephemeral keys", err)

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

func loadOrCreateKeys() (*quic.StatelessResetKey, []byte, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}

	execDir := filepath.Dir(execPath)
	keyDir := filepath.Join(execDir, "key")
	resetKeyFile := filepath.Join(keyDir, ".mosdns_stateless_reset.key")
	sessionKeyFile := filepath.Join(keyDir, ".mosdns_session_ticket.key")

	resetKey, err := loadOrCreateSingleKey(resetKeyFile, keyDir, "stateless reset")
	if err != nil {
		return nil, nil, err
	}

	sessionKey, err := loadOrCreateSingleKey(sessionKeyFile, keyDir, "session ticket")
	if err != nil {
		return nil, nil, err
	}

	var quicResetKey quic.StatelessResetKey
	copy(quicResetKey[:], resetKey)

	return &quicResetKey, sessionKey, nil
}

func loadOrCreateSingleKey(keyFile string, keyDir string, keyType string) ([]byte, error) {
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		log.Printf("[INFO] Loaded %s key from: %s", keyType, keyFile)
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, err
	}

	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return nil, err
	}

	log.Printf("[INFO] Created new %s key: %s", keyType, keyFile)
	return key, nil
}

type cert[T tls.Certificate | eTLS.Certificate] struct {
	ptr atomic.Pointer[T]
}

func (c *cert[T]) get() *T {
	return c.ptr.Load()
}

func (c *cert[T]) set(newCert *T) {
	c.ptr.Store(newCert)
}

func tryCreateWatchCert[T tls.Certificate | eTLS.Certificate](certFile string, keyFile string, createFunc func(string, string) (T, error), logger *zap.Logger) (*cert[T], error) {
	c, err := createFunc(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	cc := &cert[T]{}
	cc.set(&c)

	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Printf("[ERROR] Failed to create certificate watcher: %v", err)
			return
		}
		defer watcher.Close()

		if err := watcher.Add(certFile); err != nil {
			log.Printf("[WARN] Failed to watch certificate file %s: %v", certFile, err)
		}
		if err := watcher.Add(keyFile); err != nil {
			log.Printf("[WARN] Failed to watch key file %s: %v", keyFile, err)
		}

		timer := time.NewTimer(0)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		reloadCert := func() {
			newCert, err := createFunc(certFile, keyFile)
			if err != nil {
				logger.Error("failed to reload certificate", zap.String("file", certFile), zap.Error(err))
				return
			}
			cc.set(&newCert)
			logger.Info("certificate reloaded successfully", zap.String("file", certFile))
		}

		needReWatch := false

		for {
			select {
			case e, ok := <-watcher.Events:
				if !ok {
					timer.Stop()
					return
				}

				log.Printf("[INFO] Certificate event: %s %v", e.Name, e.Op)

				if e.Has(fsnotify.Remove) || e.Has(fsnotify.Rename) {
					log.Printf("[INFO] Certificate file %s was removed/renamed, re-watching original paths", e.Name)
					needReWatch = true

					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(2 * time.Second)
					continue
				}

				if e.Has(fsnotify.Chmod) {
					continue
				}

				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(2 * time.Second)

			case <-timer.C:
				log.Printf("[INFO] Certificate reload timer fired")
				if needReWatch {
					needReWatch = false
					_ = watcher.Remove(certFile)
					_ = watcher.Remove(keyFile)
					if err := watcher.Add(certFile); err != nil {
						log.Printf("[WARN] Failed to re-watch certFile %s: %v", certFile, err)
					}
					if err := watcher.Add(keyFile); err != nil {
						log.Printf("[WARN] Failed to re-watch keyFile %s: %v", keyFile, err)
					}
				}
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

	c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair, s.opts.Logger)
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

		// Restrict curves to disable heavy Post-Quantum algorithms (ML-KEM) and reduce CPU usage
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},

		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := c.get()
			if cert == nil {
				return nil, errors.New("certificate not available")
			}

			// SNI filtering with silent fallback
			if allowedSNI != "" && chi.ServerName != "" && chi.ServerName != allowedSNI {
				return nil, errors.New("invalid sni")
			}

			return cert, nil
		},
	}, &quic.Config{
		Allow0RTT:                      true,
        InitialStreamReceiveWindow:     16 * 1024,
        MaxStreamReceiveWindow:         512 * 1024,
        InitialConnectionReceiveWindow: 32 * 1024,
        MaxConnectionReceiveWindow:     1024 * 1024,
        MaxIncomingStreams:              1000,
	})
}

func (s *Server) CreateETLSListner(l net.Listener, nextProtos []string, allowedSNI string) (net.Listener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}

	c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, eTLS.LoadX509KeyPair, s.opts.Logger)
	if err != nil {
		return nil, err
	}

	return eTLS.NewListener(l, &eTLS.Config{
		SessionTicketKey: tlsSessionTicketKey,
		KernelTX:         s.opts.KernelTX,
		KernelRX:         s.opts.KernelRX,
		AllowEarlyData:   true,
		MaxEarlyData:     16384,
		NextProtos:       nextProtos,

		CertificateCompressionPreferences: []eTLS.CertificateCompressionAlgorithm{
			eTLS.Brotli,
			eTLS.Zlib,
		},

		MaxRecordSize: 1252,

		PreferCipherSuites: true,
		CipherSuites: []uint16{
			eTLS.TLS_AES_128_GCM_SHA256,
			eTLS.TLS_CHACHA20_POLY1305_SHA256,
			eTLS.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			eTLS.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},

		CurvePreferences: []eTLS.CurveID{
			eTLS.X25519,
			eTLS.CurveP256,
		},

		Defaults: eTLS.Defaults{
			AllSecureCipherSuites: false,
			AllSecureCurves:       false,
		},

		GetCertificate: func(chi *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			cert := c.get()
			if cert == nil {
				return nil, errors.New("certificate not available")
			}

			if allowedSNI != "" && chi.ServerName != "" && chi.ServerName != allowedSNI {
				return nil, errors.New("invalid sni")
			}

			return cert, nil
		},
	}), nil
}
