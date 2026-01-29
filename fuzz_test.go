package sacn

import (
	"bytes"
	"testing"
)

func FuzzParsePacket(f *testing.F) {
	cid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	validPacket := BuildDataPacket(1, 0, "test", cid, make([]byte, 512))
	f.Add(validPacket)
	f.Add(BuildDataPacket(1, 0, "test", cid, make([]byte, 100)))
	f.Add(BuildDataPacket(63999, 255, "long source name here", cid, make([]byte, 512)))
	f.Add(BuildDiscoveryPacket("test", cid, 0, 0, []uint16{1, 2, 3}))
	f.Add([]byte{})
	f.Add(make([]byte, 125))
	f.Add(make([]byte, 126))
	f.Add(make([]byte, 638))

	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := ParsePacket(data)
		if err != nil {
			return
		}
		switch p := pkt.(type) {
		case *DataPacket:
			if p.DataLen > 512 {
				t.Fatalf("data length should be <= 512, got %d", p.DataLen)
			}
		case *DiscoveryPacket:
			for _, u := range p.Universes {
				if u < 1 || u > 63999 {
					t.Fatalf("universe out of range: %d", u)
				}
			}
		}
	})
}

func FuzzBuildParseRoundtrip(f *testing.F) {
	f.Add(uint16(1), uint8(0), "test", make([]byte, 512))
	f.Add(uint16(63999), uint8(255), "source", make([]byte, 100))
	f.Add(uint16(100), uint8(128), "", make([]byte, 0))
	f.Add(uint16(1), uint8(0), "a very long source name that exceeds normal limits", make([]byte, 512))

	f.Fuzz(func(t *testing.T, universe uint16, seq uint8, sourceName string, dmxInput []byte) {
		if universe < 1 || universe > 63999 {
			return
		}
		cid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		packet := BuildDataPacket(universe, seq, sourceName, cid, dmxInput)
		pkt, err := ParsePacket(packet)
		if err != nil {
			t.Fatalf("failed to parse packet we just built: %v", err)
		}
		dataPkt, ok := pkt.(*DataPacket)
		if !ok {
			t.Fatalf("expected DataPacket, got %T", pkt)
		}
		if dataPkt.Universe != universe {
			t.Fatalf("universe mismatch: sent %d, got %d", universe, dataPkt.Universe)
		}
		expectedLen := len(dmxInput)
		if expectedLen > 512 {
			expectedLen = 512
		}
		if !bytes.Equal(dataPkt.Data[:expectedLen], dmxInput[:expectedLen]) {
			t.Fatalf("dmx data mismatch")
		}
	})
}

func FuzzDiscoveryRoundtrip(f *testing.F) {
	f.Add("test", uint8(0), uint8(0), []byte{0, 1, 0, 2, 0, 3})

	f.Fuzz(func(t *testing.T, sourceName string, page, lastPage uint8, universeBytes []byte) {
		universes := make([]uint16, 0, len(universeBytes)/2)
		for i := 0; i+1 < len(universeBytes); i += 2 {
			u := uint16(universeBytes[i])<<8 | uint16(universeBytes[i+1])
			if u >= 1 && u <= 63999 {
				universes = append(universes, u)
			}
		}
		if len(universes) == 0 {
			return
		}
		cid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		packet := BuildDiscoveryPacket(sourceName, cid, page, lastPage, universes)
		pkt, err := ParsePacket(packet)
		if err != nil {
			t.Fatalf("failed to parse discovery packet: %v", err)
		}
		discPkt, ok := pkt.(*DiscoveryPacket)
		if !ok {
			t.Fatalf("expected DiscoveryPacket, got %T", pkt)
		}
		if discPkt.Page != page {
			t.Fatalf("page mismatch: sent %d, got %d", page, discPkt.Page)
		}
		if discPkt.LastPage != lastPage {
			t.Fatalf("lastPage mismatch: sent %d, got %d", lastPage, discPkt.LastPage)
		}
		if len(discPkt.Universes) != len(universes) {
			t.Fatalf("universe count mismatch: sent %d, got %d", len(universes), len(discPkt.Universes))
		}
	})
}
