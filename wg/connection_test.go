package wg

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSnapshotState(t *testing.T) {
	const (
		Client1 = "127.0.0.1:1111"
		Client2 = "127.0.0.2:2222"
	)
	tMinus1 := time.Now().Add(-1 * time.Minute)
	tMinus10 := time.Now().Add(-10 * time.Minute)

	addr1, err := net.ResolveUDPAddr("udp", Client1)
	if err != nil {
		t.Fatalf("unable to resolve addr1: %v", err)
	}
	addr2, err := net.ResolveUDPAddr("udp", Client2)
	if err != nil {
		t.Fatalf("unable to resolve addr2: %v", err)
	}

	pubKey1 := wgtypes.Key(bytes.Repeat([]byte{0x01}, wgtypes.KeyLen))
	pubKey2 := wgtypes.Key(bytes.Repeat([]byte{0x02}, wgtypes.KeyLen))

	devices := []*wgtypes.Device{
		&wgtypes.Device{
			Name: "wg0",
			Peers: []wgtypes.Peer{
				wgtypes.Peer{
					PublicKey:         pubKey1,
					Endpoint:          addr1,
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      200,
					TransmitBytes:     200,
				},
				wgtypes.Peer{
					PublicKey:         pubKey2,
					Endpoint:          addr2,
					LastHandshakeTime: tMinus10,
					ReceiveBytes:      300,
					TransmitBytes:     300,
				},
			},
		},
	}

	connMap := NewConnectionMap()
	connMap.Snapshot(devices)

	connMap.Range(func(k, v any) bool {
		conn := v.(*Connection)
		if got, want := conn.State(), ConnectionUndefined; got != want {
			t.Fatalf("unexpected first conn state: got %v, want %v", got, want)
			return false
		}
		return true
	})

	devices[0].Peers[0].TransmitBytes = 300
	connMap.Snapshot(devices)

	conn, _ := connMap.Load(Client1)
	if got, want := conn.(*Connection).State(), ConnectionOpened; got != want {
		t.Fatalf("unexpected second conn state %s: got %v, want %v", Client1, got, want)
	}
	conn, _ = connMap.Load(Client2)
	if got, want := conn.(*Connection).State(), ConnectionInactive; got != want {
		t.Fatalf("unexpected second conn state %s: got %v, want %v", Client1, got, want)
	}
}

func TestState(t *testing.T) {
	tMinus1 := time.Now().Add(-1 * time.Minute)
	tMinus2 := time.Now().Add(-2 * time.Minute)
	tMinus10 := time.Now().Add(-10 * time.Minute)

	testCases := []struct {
		name        string
		conn        *Connection
		expectState ConnectionState
	}{
		{
			name: "nil",
			conn: &Connection{
				prev:   nil,
				curr:   nil,
				opened: false,
			},
			expectState: ConnectionUndefined,
		},
		{
			name: "half nil",
			conn: &Connection{
				prev:   nil,
				curr:   &wgtypes.Peer{},
				opened: false,
			},
			expectState: ConnectionUndefined,
		},
		{
			name: "empty",
			conn: &Connection{
				prev:   &wgtypes.Peer{},
				curr:   &wgtypes.Peer{},
				opened: false,
			},
			expectState: ConnectionInactive,
		},
		{
			name: "handshake check 0",
			conn: &Connection{
				prev:   &wgtypes.Peer{},
				curr:   &wgtypes.Peer{LastHandshakeTime: tMinus2},
				opened: false,
			},
			expectState: ConnectionOpened,
		},
		{
			name: "handshake check 1",
			conn: &Connection{
				prev:   &wgtypes.Peer{LastHandshakeTime: tMinus2},
				curr:   &wgtypes.Peer{LastHandshakeTime: tMinus1},
				opened: true,
			},
			expectState: ConnectionEstablished,
		},
		{
			name: "transfer check equal all open false",
			conn: &Connection{
				prev: &wgtypes.Peer{
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      100,
					TransmitBytes:     100,
				},
				curr: &wgtypes.Peer{
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      100,
					TransmitBytes:     100,
				},
				opened: false,
			},
			expectState: ConnectionOpened,
		},
		{
			name: "transfer check equal all open true",
			conn: &Connection{
				prev: &wgtypes.Peer{
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      100,
					TransmitBytes:     100,
				},
				curr: &wgtypes.Peer{
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      100,
					TransmitBytes:     100,
				},
				opened: true,
			},
			expectState: ConnectionEstablished,
		},
		{
			name: "transfer check rcv diff",
			conn: &Connection{
				prev: &wgtypes.Peer{
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      100,
					TransmitBytes:     100,
				},
				curr: &wgtypes.Peer{
					LastHandshakeTime: tMinus1,
					ReceiveBytes:      200,
					TransmitBytes:     100,
				},
				opened: true,
			},
			expectState: ConnectionEstablished,
		},
		{
			name: "transer check snd diff",
			conn: &Connection{
				prev: &wgtypes.Peer{
					LastHandshakeTime: tMinus10,
					ReceiveBytes:      100,
					TransmitBytes:     100,
				},
				curr: &wgtypes.Peer{
					LastHandshakeTime: tMinus10,
					ReceiveBytes:      100,
					TransmitBytes:     200,
				},
				opened: true,
			},
			expectState: ConnectionEstablished,
		},
		{
			name: "transfer check eq",
			conn: &Connection{
				prev: &wgtypes.Peer{
					LastHandshakeTime: tMinus10,
					ReceiveBytes:      100,
					TransmitBytes:     200,
				},
				curr: &wgtypes.Peer{
					LastHandshakeTime: tMinus10,
					ReceiveBytes:      100,
					TransmitBytes:     200,
				},
				opened: true,
			},
			expectState: ConnectionClosed,
		},
	}

	for i, tc := range testCases {
		if got, want := tc.conn.State(), tc.expectState; got != want {
			t.Errorf("case #%d %s, unexpected state: got %v, want %v", i, tc.name, got.String(), want.String())
		}
	}
}
