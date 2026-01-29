package sacn

import (
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

type Receiver struct {
	conn    *ipv4.PacketConn
	rawConn net.PacketConn
	handler func(src *net.UDPAddr, pkt interface{})
	done    chan struct{}
}

func NewReceiver(ifaceName string) (*Receiver, error) {
	c, err := net.ListenPacket("udp4", ":5568")
	if err != nil {
		return nil, err
	}

	p := ipv4.NewPacketConn(c)

	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			c.Close()
			return nil, err
		}
		p.SetMulticastInterface(iface)
	}

	return &Receiver{
		conn:    p,
		rawConn: c,
		done:    make(chan struct{}),
	}, nil
}

func (r *Receiver) JoinUniverse(iface *net.Interface, universe uint16) error {
	group := net.IPv4(239, 255, byte(universe>>8), byte(universe&0xff))
	return r.conn.JoinGroup(iface, &net.UDPAddr{IP: group})
}

func (r *Receiver) JoinDiscovery(iface *net.Interface) error {
	return r.conn.JoinGroup(iface, DiscoveryAddr)
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
	r.rawConn.Close()
}

func (r *Receiver) receiveLoop() {
	buf := make([]byte, 638)

	for {
		select {
		case <-r.done:
			return
		default:
		}

		r.rawConn.SetReadDeadline(time.Now().Add(1 * time.Second))
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
