// Package pcapdata provides a pure-Go (no cgo/libpcap) reader for both
// classic pcap and pcapng capture files, built on gopacket/pcapgo.
package pcapdata

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// classic pcap magic numbers (little/big endian, micro/nano timestamp resolution).
const (
	magicPcapLE     = 0xa1b2c3d4
	magicPcapBE     = 0xd4c3b2a1
	magicPcapNsLE   = 0xa1b23c4d
	magicPcapNsBE   = 0x4d3cb2a1
	magicPcapNgB0B0 = 0x0a0d0d0a
)

// Reader streams decoded packets from a pcap or pcapng file.
type Reader struct {
	file     *os.File
	source   gopacket.PacketDataSource
	linkType layers.LinkType
}

// Packet is a single decoded frame plus its capture metadata.
type Packet struct {
	Data gopacket.Packet
	Info gopacket.CaptureInfo
	Num  int // 1-based packet index within the file
}

// Open detects the capture format (pcap vs pcapng) and returns a Reader.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := peekMagic(br)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("read magic from %s: %w", path, err)
	}

	switch magic {
	case magicPcapLE, magicPcapBE, magicPcapNsLE, magicPcapNsBE:
		r, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("open pcap %s: %w", path, err)
		}
		return &Reader{file: f, source: r, linkType: r.LinkType()}, nil
	case magicPcapNgB0B0:
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("open pcapng %s: %w", path, err)
		}
		return &Reader{file: f, source: r, linkType: r.LinkType()}, nil
	default:
		f.Close()
		return nil, fmt.Errorf("%s: unrecognized capture format (magic %#08x)", path, magic)
	}
}

func peekMagic(br *bufio.Reader) (uint32, error) {
	b, err := br.Peek(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// LinkType returns the link-layer type declared by the capture file.
func (r *Reader) LinkType() layers.LinkType {
	return r.linkType
}

// Close releases the underlying file handle.
func (r *Reader) Close() error {
	return r.file.Close()
}

// Next decodes and returns the next packet, or io.EOF when the capture ends.
func (r *Reader) Next() (Packet, error) {
	data, ci, err := r.source.ReadPacketData()
	if err != nil {
		return Packet{}, err
	}
	// DecodeStreamsAsDatagrams is deliberately left false: it makes
	// gopacket speculatively decode TCP payloads as app-layer protocols
	// (e.g. TLS on port 443) one segment at a time with no stream
	// reassembly, which misfires constantly on any real capture (a single
	// TLS record routinely spans several TCP segments). pcapdigger does
	// its own best-effort TLS/DNS/HTTP parsing directly off tcp.Payload,
	// so nothing here depends on that heuristic decode path.
	pkt := gopacket.NewPacket(data, r.linkType, gopacket.DecodeOptions{
		Lazy:               true,
		NoCopy:             true,
		SkipDecodeRecovery: true,
	})
	return Packet{Data: pkt, Info: ci}, nil
}

// Walk calls fn for every packet in the capture, stopping at the first error
// returned by fn (other than nil) or at end of file.
func (r *Reader) Walk(fn func(Packet) error) error {
	n := 0
	for {
		pkt, err := r.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read packet %d: %w", n+1, err)
		}
		n++
		pkt.Num = n
		if err := fn(pkt); err != nil {
			return err
		}
	}
}
