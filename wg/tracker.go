package wg

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/turekt/wgmon/hook"
	"github.com/turekt/wgmon/network"
	"golang.zx2c4.com/wireguard/wgctrl"
)

var tickInterval = 2 * time.Minute

type Tracker struct {
	client  *wgctrl.Client
	connMap *ConnectionMap
	monitor network.Monitor
	webhook string
	ticker  *time.Ticker
}

func NewTracker(monitor network.Monitor, webhook string) (*Tracker, error) {
	w, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	return &Tracker{
		client:  w,
		connMap: NewConnectionMap(),
		monitor: monitor,
		webhook: webhook,
		ticker:  nil,
	}, nil
}

func (t *Tracker) connSnapshot() error {
	devices, err := t.client.Devices()
	if err != nil {
		return err
	}

	t.connMap.Snapshot(devices)
	return nil
}

func (t *Tracker) reportNewConn() {
	t.connMap.Range(func(k, v any) bool {
		conn := v.(*Connection)
		switch s := conn.State(); s {
		case ConnectionOpened:
			go func() {
				if err := hook.PostState(t.webhook, k.(string), conn.ID(), s.String()); err != nil {
					slog.Error("post state error on conn change", "state", s, "error", err)
				}
			}()
		}
		return true
	})
}

func (t *Tracker) initTicker() {
	// initiate ticker that checks connections every n minutes
	t.ticker = time.NewTicker(tickInterval)

	go func() {
		for tick := range t.ticker.C {
			slog.Info("tick", "time", tick)
			if err := t.connSnapshot(); err != nil {
				slog.Error("wg show error", "error", err)
			}

			// each conn is checked for potential closure and removed
			var connCount atomic.Int32
			t.connMap.Range(func(k, v any) bool {
				connCount.Add(1)
				conn := v.(*Connection)
				switch s := conn.State(); s {
				case ConnectionClosed:
					go func() {
						if err := hook.PostState(t.webhook, k.(string), conn.ID(), s.String()); err != nil {
							slog.Error("post state error during tick", "error", err)
						}
					}()
					fallthrough
				case ConnectionInactive:
					t.connMap.Delete(k)
					connCount.Add(-1)
				}
				return true
			})

			// if there is nothing in connection map then stop ticker
			// no one is connected
			if connCount.Load() == 0 {
				slog.Info("stopping ticker")
				t.ticker.Stop()
				t.ticker = nil
			}
		}
	}()
}

func (t *Tracker) handlePacket() {
	for i := range t.monitor.PacketChan() {
		details := network.NewPacketDetails(i)
		if t.ticker == nil {
			// report this initial packet
			go func() {
				if err := hook.PostPacketDetails(t.webhook, details); err != nil {
					slog.Error("post packet details error", "error", err)
				}
			}()
			t.initTicker()
		}

		if conn, ok := t.connMap.Load(details.RemoteAddr()); ok && conn.(*Connection).Opened() {
			// if opened, connection is already reported
			continue
		}

		// snapshot wg show all dump
		if err := t.connSnapshot(); err != nil {
			slog.Error("wg show data failed", "error", err)
			continue
		}
		t.reportNewConn()
	}
}

func (t *Tracker) Start() {
	t.startWatch(t.monitor.Watch)
}

func (t *Tracker) startWatch(watchFunc func()) error {
	if err := t.monitor.Open(); err != nil {
		slog.Error("error opening handle", "error", err)
		return err
	}

	go watchFunc()
	slog.Info("initiating wg peer monitoring", "monitor", t.monitor)
	t.handlePacket()
	return nil
}

func (t *Tracker) Stop() {
	ct := make(chan byte, 1)
	go func() {
		t.monitor.Close()
		ct <- byte(0x01)
	}()

	select {
	case <-ct:
	case <-time.After(3 * time.Second):
		t.monitor.ShutdownChan() <- byte(0x01)
	}

	if t.ticker != nil {
		t.ticker.Stop()
		t.ticker = nil
	}
}
