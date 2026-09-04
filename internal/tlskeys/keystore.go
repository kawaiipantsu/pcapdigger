// Package tlskeys loads TLS decryption secrets from
// ~/.config/pcapdigger/tls: NSS-format key-log files (*.log, *.keylog,
// *.txt -- the SSLKEYLOGFILE format written by browsers, curl, OpenSSL,
// and most other TLS stacks when asked to), RSA private keys (*.pem,
// *.key) for legacy static-RSA key exchange, and a simple
// "identity:hex-key" PSK file (*.psk) for PSK-family cipher suites.
// Nothing here ever attempts key recovery without one of these explicit,
// user-supplied secrets.
package tlskeys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeylogSecret is one NSS key-log entry, keyed by its label (CLIENT_RANDOM,
// CLIENT_TRAFFIC_SECRET_0, SERVER_HANDSHAKE_TRAFFIC_SECRET, etc.).
type KeylogSecret struct {
	Label  string
	Secret []byte
}

// Store holds every decryption secret loaded from the TLS keys directory.
type Store struct {
	// Keylog maps a lowercase-hex client_random to every secret logged
	// against it (a connection logs several labels: one for TLS 1.2's
	// CLIENT_RANDOM, or several for TLS 1.3's staged traffic secrets).
	Keylog map[string][]KeylogSecret
	// RSAKeys are every RSA private key loaded, tried in order against
	// each RSA-key-exchange ClientKeyExchange until one decrypts cleanly.
	RSAKeys []*rsa.PrivateKey
	// PSKs maps an identity string to its key bytes.
	PSKs map[string][]byte
}

// Load reads every recognized file in dir. A missing directory is not an
// error -- it just means no decryption secrets are available.
func Load(dir string) (*Store, error) {
	s := &Store{Keylog: map[string][]KeylogSecret{}, PSKs: map[string][]byte{}}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		ext := strings.ToLower(filepath.Ext(e.Name()))
		switch ext {
		case ".log", ".keylog", ".txt":
			if err := s.loadKeylogFile(path); err != nil {
				return nil, fmt.Errorf("keylog %s: %w", path, err)
			}
		case ".pem", ".key":
			if err := s.loadRSAKeyFile(path); err != nil {
				return nil, fmt.Errorf("rsa key %s: %w", path, err)
			}
		case ".psk":
			if err := s.loadPSKFile(path); err != nil {
				return nil, fmt.Errorf("psk file %s: %w", path, err)
			}
		}
	}
	return s, nil
}

// Empty reports whether the store has no usable secrets at all.
func (s *Store) Empty() bool {
	return s == nil || (len(s.Keylog) == 0 && len(s.RSAKeys) == 0 && len(s.PSKs) == 0)
}

func (s *Store) loadKeylogFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue // malformed/unrecognized line; skip rather than fail the whole file
		}
		label, clientRandomHex, secretHex := fields[0], strings.ToLower(fields[1]), fields[2]
		if label == "RSA" {
			// OpenSSL also logs "RSA <8-byte-session-id-hex> <premaster-hex>"
			// entries, keyed by session ID rather than client_random; not
			// useful for matching against a captured ClientHello, so skip.
			continue
		}
		secret, err := hex.DecodeString(secretHex)
		if err != nil {
			continue
		}
		s.Keylog[clientRandomHex] = append(s.Keylog[clientRandomHex], KeylogSecret{Label: label, Secret: secret})
	}
	return nil
}

func (s *Store) loadRSAKeyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		key, err := parseRSAPrivateKey(block)
		if err != nil {
			continue // not every PEM block is a private key we can use; skip it
		}
		s.RSAKeys = append(s.RSAKeys, key)
	}
	return nil
}

func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	return rsaKey, nil
}

func (s *Store) loadPSKFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		identity, keyHex, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, err := hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil {
			continue
		}
		s.PSKs[strings.TrimSpace(identity)] = key
	}
	return nil
}
