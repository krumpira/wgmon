package network

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/netlink"
)

type Monitor interface {
	Open() error
	Watch()
	Close()
	ShutdownChan() chan byte
	PacketChan() chan gopacket.Packet
}

type NFLogMonitor struct {
	group uint16
	conn  *NetfilterConn
	ns    int
	C     chan gopacket.Packet
	S     chan byte
}

func NewNFLogMonitor(group uint16, ns int) Monitor {
	return &NFLogMonitor{
		group: group,
		ns:    ns,
		S:     make(chan byte, 1),
		C:     make(chan gopacket.Packet, 1),
	}
}

func (n *NFLogMonitor) ShutdownChan() chan byte {
	return n.S
}

func (n *NFLogMonitor) PacketChan() chan gopacket.Packet {
	return n.C
}

func (n *NFLogMonitor) Open() error {
	var err error
	n.conn, err = BindNFLog(n.group, n.ns)
	if err != nil {
		return fmt.Errorf("failed to bind group %d: %v", n.group, err)
	}
	return nil
}

func (n *NFLogMonitor) Watch() {
	for {
		select {
		case <-n.S:
			n.Close()
			break
		default:
			msgs, err := n.conn.Receive()
			if err != nil {
				continue
			}

			for _, m := range msgs {
				attrs, err := netlink.UnmarshalAttributes(m.Data[4:])
				if err != nil {
					fmt.Printf("unmarshal failed %v\n", err)
					continue
				}
				var p gopacket.Packet
				for _, attr := range attrs {
					if attr.Type == NFULA_PAYLOAD {
						payload := attr.Data
						switch payload[0] >> 4 {
						case 6:
							p = gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.NoCopy)
						default:
							p = gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.NoCopy)
						}
						break
					}
				}
				if p != nil {
					n.C <- p
				}
			}
		}
	}
}

func (n *NFLogMonitor) Close() {
	close(n.C)
	close(n.S)
	if n.conn != nil {
		n.conn.Close()
	}
}

type BPFMonitor struct {
	filter string
	intf   string
	C      chan gopacket.Packet
	S      chan byte
	handle *pcap.Handle
}

func NewBPFMonitor(intf, filter string) Monitor {
	return &BPFMonitor{
		filter: filter,
		intf:   intf,
		S:      make(chan byte, 1),
		C:      make(chan gopacket.Packet, 1),
	}
}

func (m *BPFMonitor) ShutdownChan() chan byte {
	return m.S
}

func (m *BPFMonitor) PacketChan() chan gopacket.Packet {
	return m.C
}

func (m *BPFMonitor) Open() error {
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

func (m *BPFMonitor) Watch() {
	packetSource := gopacket.NewPacketSource(m.handle, m.handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			m.C <- packet
		case <-m.S:
			m.Close()
			break
		}
	}
}

func (m *BPFMonitor) Close() {
	close(m.C)
	close(m.S)
	if m.handle != nil {
		m.handle.Close()
	}
}
