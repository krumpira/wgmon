package network

import (
	"net"
	"time"

	"github.com/google/gopacket"
)

type PacketDetails struct {
	SrcIP   string
	DstIP   string
	SrcPort string
	DstPort string
	Time    time.Time
	L4Proto string
	L5Proto string
}

func NewPacketDetails(packet gopacket.Packet) *PacketDetails {
	var srcPort, dstPort, srcIP, dstIP gopacket.Endpoint
	var layer4, layer5 string

	packetTime := time.Now()
	if meta := packet.Metadata(); meta != nil && meta.Length != 0 {
		packetTime = meta.Timestamp
	}
	if net := packet.NetworkLayer(); net != nil {
		srcIP, dstIP = net.NetworkFlow().Endpoints()
	}
	if transport := packet.TransportLayer(); transport != nil {
		srcPort, dstPort = transport.TransportFlow().Endpoints()
		layer4 = transport.LayerType().String()
	}
	if application := packet.ApplicationLayer(); application != nil {
		layer5 = application.LayerType().String()
	}
	return &PacketDetails{
		SrcIP:   srcIP.String(),
		DstIP:   dstIP.String(),
		SrcPort: srcPort.String(),
		DstPort: dstPort.String(),
		Time:    packetTime,
		L4Proto: layer4,
		L5Proto: layer5,
	}
}

func (p *PacketDetails) RemoteAddr() string {
	return net.JoinHostPort(p.SrcIP, p.SrcPort)
}

func (p *PacketDetails) Destination() string {
	return net.JoinHostPort(p.DstIP, p.DstPort)
}
