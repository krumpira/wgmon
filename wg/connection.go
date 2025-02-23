package wg

import (
	"fmt"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type ConnectionState int

const (
	ConnectionUndefined ConnectionState = iota
	ConnectionOpened
	ConnectionEstablished
	ConnectionClosed
	ConnectionInactive
)

func (cs ConnectionState) String() (str string) {
	switch cs {
	case ConnectionUndefined:
		str = "undefined"
	case ConnectionOpened:
		str = "opened"
	case ConnectionEstablished:
		str = "established"
	case ConnectionClosed:
		str = "closed"
	case ConnectionInactive:
		str = "inactive"
	default:
		str = "unspecified"
	}
	return
}

var idleTimeout = 5 * time.Minute

type Connection struct {
	mu     sync.RWMutex
	device string
	prev   *wgtypes.Peer
	curr   *wgtypes.Peer
	opened bool
}

func (c *Connection) State() ConnectionState {
	connRunBasedOnFlag := func() ConnectionState {
		if c.opened {
			// conn already registered, nothing new
			return ConnectionEstablished
		}

		// newly opened conn
		c.setOpened(true)
		return ConnectionOpened
	}

	if c.prev == nil || c.curr == nil {
		return ConnectionUndefined
	}

	if c.prev.LastHandshakeTime.Before(c.curr.LastHandshakeTime) {
		// difference in handshake time indicates running conn
		return connRunBasedOnFlag()
	}

	if c.curr.LastHandshakeTime.Equal(c.prev.LastHandshakeTime) {
		if c.IsTransferring() {
			// no change in handshake but difference in
			// transferred bytes indicates running conn
			return connRunBasedOnFlag()
		}
	}

	// no change in handshake and no change in transferred bytes
	if c.curr.LastHandshakeTime.Before(time.Now().Add(-1 * idleTimeout)) {
		// conn idle for too long, disconnected
		if c.Opened() {
			c.setOpened(false)
			return ConnectionClosed
		}

		return ConnectionInactive
	}

	// conn not eligible to register as disconnected
	return connRunBasedOnFlag()
}

func (c *Connection) IsTransferring() bool {
	return c.prev.ReceiveBytes < c.curr.ReceiveBytes || c.prev.TransmitBytes < c.curr.TransmitBytes
}

func (c *Connection) setOpened(state bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opened = state
}

func (c *Connection) Opened() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.opened
}

func (c *Connection) ID() string {
	return fmt.Sprintf("%s:%s", c.device, c.curr.PublicKey.String())
}

type ConnectionMap struct {
	sync.Map
}

func NewConnectionMap() *ConnectionMap {
	return &ConnectionMap{}
}

func (t *ConnectionMap) Snapshot(devices []*wgtypes.Device) {
	for _, dev := range devices {
		for _, peer := range dev.Peers {
			key := peer.Endpoint.String()
			conn := &Connection{device: dev.Name}
			if v, ok := t.Load(key); ok {
				conn = v.(*Connection)
			}

			conn.prev = conn.curr
			conn.curr = &peer
			t.Store(key, conn)
		}
	}
}
