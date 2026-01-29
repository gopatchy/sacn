package sacn

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	Port = 5568

	VectorRootE131Data      = 0x00000004
	VectorRootE131Extended  = 0x00000008
	VectorE131DataPacket    = 0x00000002
	VectorE131Discovery     = 0x00000002
	VectorDMPSetProperty    = 0x02
	VectorUniverseDiscovery = 0x00000001
)

var (
	PacketIdentifier = [12]byte{
		0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00,
	}

	DiscoveryAddr = &net.UDPAddr{
		IP:   net.IPv4(239, 255, 250, 214),
		Port: Port,
	}

	ErrInvalidHeader  = errors.New("invalid sACN header")
	ErrPacketTooShort = errors.New("packet too short")
	ErrInvalidVector  = errors.New("invalid vector")
)

type DataPacket struct {
	CID        [16]byte
	SourceName string
	Priority   uint8
	Sequence   uint8
	Universe   uint16
	Data       [512]byte
	DataLen    int
}

type DiscoveryPacket struct {
	CID        [16]byte
	SourceName string
	Page       uint8
	LastPage   uint8
	Universes  []uint16
}

func MulticastAddr(universe uint16) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IPv4(239, 255, byte(universe>>8), byte(universe&0xff)),
		Port: Port,
	}
}

func ParsePacket(data []byte) (interface{}, error) {
	if len(data) < 22 {
		return nil, ErrPacketTooShort
	}

	if data[4] != PacketIdentifier[0] || data[5] != PacketIdentifier[1] ||
		data[6] != PacketIdentifier[2] || data[7] != PacketIdentifier[3] {
		return nil, ErrInvalidHeader
	}

	rootVector := binary.BigEndian.Uint32(data[18:22])

	switch rootVector {
	case VectorRootE131Data:
		return parseDataPacket(data)
	case VectorRootE131Extended:
		return parseExtendedPacket(data)
	default:
		return nil, ErrInvalidVector
	}
}

func parseDataPacket(data []byte) (*DataPacket, error) {
	if len(data) < 126 {
		return nil, ErrPacketTooShort
	}

	framingVector := binary.BigEndian.Uint32(data[40:44])
	if framingVector != VectorE131DataPacket {
		return nil, ErrInvalidVector
	}

	if data[117] != VectorDMPSetProperty {
		return nil, ErrInvalidVector
	}

	propCount := binary.BigEndian.Uint16(data[123:125])
	if propCount < 1 {
		return nil, ErrPacketTooShort
	}

	dmxLen := int(propCount) - 1
	if dmxLen > 512 {
		dmxLen = 512
	}

	if len(data) < 126+dmxLen {
		return nil, ErrPacketTooShort
	}

	pkt := &DataPacket{
		SourceName: strings.TrimRight(string(data[44:108]), "\x00"),
		Priority:   data[108],
		Sequence:   data[111],
		Universe:   binary.BigEndian.Uint16(data[113:115]),
		DataLen:    dmxLen,
	}
	copy(pkt.CID[:], data[22:38])
	copy(pkt.Data[:], data[126:126+dmxLen])

	return pkt, nil
}

func parseExtendedPacket(data []byte) (interface{}, error) {
	if len(data) < 118 {
		return nil, ErrPacketTooShort
	}

	framingVector := binary.BigEndian.Uint32(data[40:44])
	if framingVector != VectorE131Discovery {
		return nil, ErrInvalidVector
	}

	if len(data) < 120 {
		return nil, ErrPacketTooShort
	}

	discoveryVector := binary.BigEndian.Uint32(data[114:118])
	if discoveryVector != VectorUniverseDiscovery {
		return nil, ErrInvalidVector
	}

	pkt := &DiscoveryPacket{
		SourceName: strings.TrimRight(string(data[44:108]), "\x00"),
		Page:       data[118],
		LastPage:   data[119],
	}
	copy(pkt.CID[:], data[22:38])

	universeCount := (len(data) - 120) / 2
	pkt.Universes = make([]uint16, 0, universeCount)
	for i := 0; i < universeCount; i++ {
		u := binary.BigEndian.Uint16(data[120+i*2 : 122+i*2])
		if u >= 1 && u <= 63999 {
			pkt.Universes = append(pkt.Universes, u)
		}
	}

	return pkt, nil
}

func BuildDataPacket(universe uint16, sequence uint8, sourceName string, cid [16]byte, data []byte) []byte {
	dataLen := len(data)
	if dataLen > 512 {
		dataLen = 512
	}

	pktLen := 126 + dataLen
	buf := make([]byte, pktLen)

	binary.BigEndian.PutUint16(buf[0:2], 0x0010)
	binary.BigEndian.PutUint16(buf[2:4], 0x0000)
	copy(buf[4:16], PacketIdentifier[:])
	rootLen := pktLen - 16
	binary.BigEndian.PutUint16(buf[16:18], 0x7000|uint16(rootLen))
	binary.BigEndian.PutUint32(buf[18:22], VectorRootE131Data)
	copy(buf[22:38], cid[:])

	framingLen := pktLen - 38
	binary.BigEndian.PutUint16(buf[38:40], 0x7000|uint16(framingLen))
	binary.BigEndian.PutUint32(buf[40:44], VectorE131DataPacket)
	copy(buf[44:108], sourceName)
	buf[108] = 100
	binary.BigEndian.PutUint16(buf[109:111], 0)
	buf[111] = sequence
	buf[112] = 0
	binary.BigEndian.PutUint16(buf[113:115], universe)

	dmpLen := 11 + dataLen
	binary.BigEndian.PutUint16(buf[115:117], 0x7000|uint16(dmpLen))
	buf[117] = VectorDMPSetProperty
	buf[118] = 0xa1
	binary.BigEndian.PutUint16(buf[119:121], 0)
	binary.BigEndian.PutUint16(buf[121:123], 1)
	binary.BigEndian.PutUint16(buf[123:125], uint16(dataLen+1))
	buf[125] = 0
	copy(buf[126:], data[:dataLen])

	return buf
}

func BuildDiscoveryPacket(sourceName string, cid [16]byte, page, lastPage uint8, universes []uint16) []byte {
	universeCount := len(universes)
	if universeCount > 512 {
		universeCount = 512
	}

	pktLen := 120 + universeCount*2
	buf := make([]byte, pktLen)

	binary.BigEndian.PutUint16(buf[0:2], 0x0010)
	binary.BigEndian.PutUint16(buf[2:4], 0x0000)
	copy(buf[4:16], PacketIdentifier[:])
	rootLen := pktLen - 16
	binary.BigEndian.PutUint16(buf[16:18], 0x7000|uint16(rootLen))
	binary.BigEndian.PutUint32(buf[18:22], VectorRootE131Extended)
	copy(buf[22:38], cid[:])

	framingLen := pktLen - 38
	binary.BigEndian.PutUint16(buf[38:40], 0x7000|uint16(framingLen))
	binary.BigEndian.PutUint32(buf[40:44], VectorE131Discovery)
	copy(buf[44:108], sourceName)
	binary.BigEndian.PutUint32(buf[108:112], 0)

	discoveryLen := pktLen - 112
	binary.BigEndian.PutUint16(buf[112:114], 0x7000|uint16(discoveryLen))
	binary.BigEndian.PutUint32(buf[114:118], VectorUniverseDiscovery)
	buf[118] = page
	buf[119] = lastPage
	for i := 0; i < universeCount; i++ {
		binary.BigEndian.PutUint16(buf[120+i*2:122+i*2], universes[i])
	}

	return buf
}

func FormatCID(cid [16]byte) string {
	return strings.ToLower(formatUUID(cid))
}

func formatUUID(b [16]byte) string {
	const hexChars = "0123456789ABCDEF"
	result := make([]byte, 36)
	idx := 0
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			result[idx] = '-'
			idx++
		}
		result[idx] = hexChars[v>>4]
		result[idx+1] = hexChars[v&0x0f]
		idx += 2
	}
	return string(result)
}
