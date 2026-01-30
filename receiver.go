package sacn

import (
	"net"
	"time"

	"github.com/gopatchy/multicast"
)

type Receiver struct {
	conn    *multicast.Conn
	handler func(src *net.UDPAddr, pkt interface{})
	done    chan struct{}
}

func NewUniverseReceiver(iface *net.Interface, universe uint16) (*Receiver, error) {
	c, err := multicast.ListenMulticastUDP("udp4", iface, MulticastAddr(universe))
	if err != nil {
		return nil, err
	}

	return &Receiver{
		conn: c,
		done: make(chan struct{}),
	}, nil
}

func NewDiscoveryReceiver(iface *net.Interface) (*Receiver, error) {
	c, err := multicast.ListenMulticastUDP("udp4", iface, DiscoveryAddr)
	if err != nil {
		return nil, err
	}

	return &Receiver{
		conn: c,
		done: make(chan struct{}),
	}, nil
}

func (r *Receiver) SetHandler(fn func(src *net.UDPAddr, pkt interface{})) {
	r.handler = fn
}

func (r *Receiver) Start() {
	go r.receiveLoop()
}

func (r *Receiver) Stop() {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
	r.conn.Close()
}

func (r *Receiver) receiveLoop() {
	buf := make([]byte, 638)

	for {
		select {
		case <-r.done:
			return
		default:
		}

		r.conn.RawConn().SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, src, err := r.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-r.done:
				return
			default:
				continue
			}
		}

		pkt, err := ParsePacket(buf[:n])
		if err != nil {
			continue
		}

		if r.handler != nil {
			r.handler(src.(*net.UDPAddr), pkt)
		}
	}
}
