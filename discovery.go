package sacn

import (
	"net"
	"sync"
	"time"
)

type Source struct {
	CID        [16]byte
	SourceName string
	IP         net.IP
	Universes  []uint16
	LastSeen   time.Time
}

type Discovery struct {
	sources  map[string]*Source
	mu       sync.RWMutex
	onChange func(*Source)
	done     chan struct{}
}

func NewDiscovery() *Discovery {
	return &Discovery{
		sources: map[string]*Source{},
		done:    make(chan struct{}),
	}
}

func (d *Discovery) SetOnChange(fn func(*Source)) {
	d.onChange = fn
}

func (d *Discovery) HandleDiscoveryPacket(src *net.UDPAddr, pkt *DiscoveryPacket) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cidStr := FormatCID(pkt.CID)

	source, exists := d.sources[cidStr]
	if !exists {
		source = &Source{
			CID: pkt.CID,
		}
		d.sources[cidStr] = source
	}

	source.SourceName = pkt.SourceName
	source.IP = src.IP
	source.Universes = pkt.Universes
	source.LastSeen = time.Now()

	if d.onChange != nil {
		d.onChange(source)
	}
}

func (d *Discovery) GetSource(cid string) *Source {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sources[cid]
}

func (d *Discovery) GetSourceByIP(ip net.IP) *Source {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, source := range d.sources {
		if source.IP != nil && source.IP.Equal(ip) {
			return source
		}
	}
	return nil
}

func (d *Discovery) GetAllSources() []*Source {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*Source, 0, len(d.sources))
	for _, source := range d.sources {
		result = append(result, source)
	}
	return result
}

func (d *Discovery) Expire() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	for cid, source := range d.sources {
		if source.LastSeen.Before(cutoff) {
			delete(d.sources, cid)
		}
	}
}

func (d *Discovery) StartCleanup() {
	go d.cleanupLoop()
}

func (d *Discovery) Stop() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

func (d *Discovery) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			d.Expire()
		}
	}
}
