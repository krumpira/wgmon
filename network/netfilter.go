package network

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Constants not found in unix.go
// https://github.com/torvalds/linux/blob/a5806cd506af5a7c19bcd596e4708b5c464bfd21/include/uapi/linux/netfilter/nfnetlink_log.h
const (
	NFULNL_COPY_PACKET = 0x02

	// nfulnl_msg_types
	NFULNL_MSG_CONFIG = 1

	// nfulnl_msg_config_cmds
	NFULNL_CFG_CMD_BIND = 1

	// nfulnl_attr_config
	NFULA_CFG_CMD  = 1
	NFULA_CFG_MODE = 2

	// nfulnl_attr_type
	NFULA_PAYLOAD = 9
	NFULA_PREFIX  = 10
)

type NetfilterConn struct {
	*netlink.Conn
}

func BindNFLog(group uint16, ns int) (*NetfilterConn, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: ns})
	if err != nil {
		return nil, err
	}
	conn := &NetfilterConn{c}
	// group 1 bind
	if _, err := conn.SendMsgConfig(group, []netlink.Attribute{
		{Type: NFULA_CFG_CMD, Data: []byte{NFULNL_CFG_CMD_BIND}},
	}); err != nil {
		return nil, err
	}
	// group 1 copy packets
	if _, err := conn.SendMsgConfig(group, []netlink.Attribute{
		{Type: NFULA_CFG_MODE, Data: []byte{0x00, 0x00, 0x00, 0x00, NFULNL_COPY_PACKET, 0x00}},
	}); err != nil {
		return nil, err
	}
	return conn, err
}

func (conn *NetfilterConn) SendMsgConfig(resid uint16, attrs []netlink.Attribute) (uint32, error) {
	cmd, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, resid)
	data := append([]byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, buf[0], buf[1]}, cmd...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	}

	reply, err := conn.Execute(req)
	if err != nil {
		return 0, err
	}

	if err := netlink.Validate(req, reply); err != nil {
		return 0, err
	}

	var seq uint32
	for _, msg := range reply {
		if seq != 0 {
			return 0, fmt.Errorf("received more than one message from the kernel")
		}
		seq = msg.Header.Sequence
	}
	return seq, nil
}
