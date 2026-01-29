package sacn

import (
	"crypto/rand"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

type Sender struct {
	conn       *net.UDPConn
	sourceName string
	cid        [16]byte
	sequences  map[uint16]uint8
	seqMu      sync.Mutex
	universes  map[uint16]bool
	done       chan struct{}
}

func NewSender(sourceName string, ifaceName string) (*Sender, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}

	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			conn.Close()
			return nil, err
		}
		p := ipv4.NewPacketConn(conn)
		if err := p.SetMulticastInterface(iface); err != nil {
			conn.Close()
			return nil, err
		}
	}

	var cid [16]byte
	rand.Read(cid[:])

	return &Sender{
		conn:       conn,
		sourceName: sourceName,
		cid:        cid,
		sequences:  map[uint16]uint8{},
		universes:  map[uint16]bool{},
		done:       make(chan struct{}),
	}, nil
}

func (s *Sender) CID() [16]byte {
	return s.cid
}

func (s *Sender) SendDMX(universe uint16, data []byte) error {
	s.seqMu.Lock()
	seq := s.sequences[universe]
	s.sequences[universe] = seq + 1
	s.seqMu.Unlock()

	pkt := BuildDataPacket(universe, seq, s.sourceName, s.cid, data)
	addr := MulticastAddr(universe)

	_, err := s.conn.WriteToUDP(pkt, addr)
	return err
}

func (s *Sender) SendDMXUnicast(addr *net.UDPAddr, universe uint16, data []byte) error {
	s.seqMu.Lock()
	seq := s.sequences[universe]
	s.sequences[universe] = seq + 1
	s.seqMu.Unlock()

	pkt := BuildDataPacket(universe, seq, s.sourceName, s.cid, data)

	_, err := s.conn.WriteToUDP(pkt, addr)
	return err
}

func (s *Sender) RegisterUniverse(universe uint16) {
	s.seqMu.Lock()
	s.universes[universe] = true
	s.seqMu.Unlock()
}

func (s *Sender) StartDiscovery() {
	go s.discoveryLoop()
}

func (s *Sender) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return s.conn.Close()
}

func (s *Sender) discoveryLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	s.sendDiscovery()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sendDiscovery()
		}
	}
}

func (s *Sender) sendDiscovery() {
	s.seqMu.Lock()
	universes := make([]uint16, 0, len(s.universes))
	for u := range s.universes {
		universes = append(universes, u)
	}
	s.seqMu.Unlock()

	if len(universes) == 0 {
		return
	}

	sort.Slice(universes, func(i, j int) bool { return universes[i] < universes[j] })

	const maxPerPage = 512
	totalPages := (len(universes) + maxPerPage - 1) / maxPerPage

	for page := 0; page < totalPages; page++ {
		start := page * maxPerPage
		end := start + maxPerPage
		if end > len(universes) {
			end = len(universes)
		}
		pkt := BuildDiscoveryPacket(s.sourceName, s.cid, uint8(page), uint8(totalPages-1), universes[start:end])
		s.conn.WriteToUDP(pkt, DiscoveryAddr)
	}
}
