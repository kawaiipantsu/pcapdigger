package tlssession

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"

	"pcapdigger/internal/pcapdata"
	"pcapdigger/internal/tlskeys"
)

// tcpChunk is one packet's payload, in capture order.
type tcpChunk struct {
	dir  Direction
	data []byte
}

// streamTCP replays every TCP packet in path in its original chronological
// order, tagging each non-empty payload with a direction based on which
// side sent the very first SYN (that side's destination port is "the
// server"). Preserving real packet order matters: e.g. the client's
// ChangeCipherSpec record can only be interpreted once the server's
// earlier ServerHello (a different direction's bytes) has been processed.
func streamTCP(t *testing.T, path string) []tcpChunk {
	t.Helper()
	r, err := pcapdata.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer r.Close()

	var chunks []tcpChunk
	serverPort := uint16(0)
	err = r.Walk(func(p pcapdata.Packet) error {
		tcp, ok := p.Data.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			return nil
		}
		if serverPort == 0 && tcp.SYN && !tcp.ACK {
			serverPort = uint16(tcp.DstPort)
		}
		if len(tcp.Payload) == 0 {
			return nil
		}
		if uint16(tcp.DstPort) == serverPort {
			chunks = append(chunks, tcpChunk{ClientToServer, append([]byte{}, tcp.Payload...)})
		} else if uint16(tcp.SrcPort) == serverPort {
			chunks = append(chunks, tcpChunk{ServerToClient, append([]byte{}, tcp.Payload...)})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", path, err)
	}
	return chunks
}

func decryptFixture(t *testing.T, pcapPath string, keys *tlskeys.Store) (clientPlain, serverPlain []byte) {
	t.Helper()
	chunks := streamTCP(t, pcapPath)

	sess := New(keys)
	for _, c := range chunks {
		for _, pt := range sess.Feed(c.dir, c.data) {
			if pt.Direction == ClientToServer {
				clientPlain = append(clientPlain, pt.Data...)
			} else {
				serverPlain = append(serverPlain, pt.Data...)
			}
		}
	}
	if !sess.Decrypted {
		t.Fatalf("session for %s never resolved keys", pcapPath)
	}
	return clientPlain, serverPlain
}

func mustLoadKeys(t *testing.T, dir string) *tlskeys.Store {
	t.Helper()
	store, err := tlskeys.Load(dir)
	if err != nil {
		t.Fatalf("load keys from %s: %v", dir, err)
	}
	return store
}

func TestDecryptViaKeylog(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "tls")
	for _, name := range []string{"gcm_rsa", "cbc_rsa", "psk_gcm"} {
		t.Run(name, func(t *testing.T) {
			// Loading the whole fixtures directory is fine even though it
			// holds keylog entries for all three connections: each
			// Session only ever looks up its own ClientHello's random.
			keys := mustLoadKeys(t, fixtures)

			clientPlain, serverPlain := decryptFixture(t, filepath.Join(fixtures, name+".pcap"), keys)
			if !bytes.Contains(clientPlain, []byte("GET / HTTP/1.0")) {
				t.Errorf("client plaintext missing HTTP request, got: %q", string(clientPlain))
			}
			if !strings.Contains(string(serverPlain), "HTTP/1.0 200 ok") {
				t.Errorf("server plaintext missing HTTP response, got: %q", string(serverPlain))
			}
		})
	}
}

func TestDecryptViaRSAKeyOnly(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "tls")
	for _, name := range []string{"gcm_rsa", "cbc_rsa"} {
		t.Run(name, func(t *testing.T) {
			// Load only the RSA private key, deliberately excluding the
			// keylog, to exercise the ClientKeyExchange RSA-decrypt path.
			full := mustLoadKeys(t, fixtures)
			keys := &tlskeys.Store{Keylog: map[string][]tlskeys.KeylogSecret{}, PSKs: map[string][]byte{}, RSAKeys: full.RSAKeys}
			if len(keys.RSAKeys) == 0 {
				t.Fatal("no RSA keys loaded from fixtures dir")
			}

			clientPlain, serverPlain := decryptFixture(t, filepath.Join(fixtures, name+".pcap"), keys)
			if !bytes.Contains(clientPlain, []byte("GET / HTTP/1.0")) {
				t.Errorf("client plaintext missing HTTP request, got: %q", string(clientPlain))
			}
			if !strings.Contains(string(serverPlain), "HTTP/1.0 200 ok") {
				t.Errorf("server plaintext missing HTTP response, got: %q", string(serverPlain))
			}
		})
	}
}

func TestDecryptViaPSKFileOnly(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata", "tls")
	// Load only the PSK identity/key file, deliberately excluding the
	// keylog, to exercise the plain-PSK premaster-construction path.
	full := mustLoadKeys(t, fixtures)
	keys := &tlskeys.Store{Keylog: map[string][]tlskeys.KeylogSecret{}, PSKs: full.PSKs}
	if len(keys.PSKs) == 0 {
		t.Fatal("no PSKs loaded from fixtures dir")
	}

	clientPlain, serverPlain := decryptFixture(t, filepath.Join(fixtures, "psk_gcm.pcap"), keys)
	if !bytes.Contains(clientPlain, []byte("GET / HTTP/1.0")) {
		t.Errorf("client plaintext missing HTTP request, got: %q", string(clientPlain))
	}
	if !strings.Contains(string(serverPlain), "HTTP/1.0 200 ok") {
		t.Errorf("server plaintext missing HTTP response, got: %q", string(serverPlain))
	}
}
