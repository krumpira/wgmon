package network

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Monitor struct {
	filter string
	intf   string
	C      chan gopacket.Packet
	S      chan byte
	handle *pcap.Handle
}

func NewMonitor(intf, filter string) *Monitor {
	return &Monitor{
		filter: filter,
		intf:   intf,
		S:      make(chan byte, 1),
		C:      make(chan gopacket.Packet, 1),
	}
}

func (m *Monitor) OpenHandle() error {
	inactive, err := pcap.NewInactiveHandle(m.intf)
	if err != nil {
		return fmt.Errorf("failed to open interface %s %w", m.intf, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(1600); err != nil {
		return fmt.Errorf("failed to set snaplen %w", err)
	}
	if err := inactive.SetPromisc(true); err != nil {
		return fmt.Errorf("failed to set promisc mode %w", err)
	}
	if err := inactive.SetTimeout(pcap.BlockForever); err != nil {
		return fmt.Errorf("failed to set timeout %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("failed to activate handle %w", err)
	}

	if err := handle.SetBPFFilter(m.filter); err != nil {
		return fmt.Errorf("failed to set bpf m.filter %s %w", m.filter, err)
	}

	m.handle = handle
	return nil
}

func (m *Monitor) Watch() {
	packetSource := gopacket.NewPacketSource(m.handle, m.handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			m.C <- packet
		case <-m.S:
			close(m.C)
			break
		}
	}
}

func (m *Monitor) Close() {
	close(m.C)
	if m.handle != nil {
		m.handle.Close()
	}
}
