package wg

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/turekt/wgmon/network"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	ServerVethName      = "veth1"
	ServerVethIP        = "10.0.0.1"
	ServerVethIPN       = ServerVethIP + "/24"
	ServerVethPeer      = ClientVethName
	ServerDeviceName    = "srv0"
	ServerWireGuardIP   = "10.10.10.1"
	ServerWireGuardPort = 3000

	ClientVethName    = "veth2"
	ClientVethIP      = "10.0.0.2"
	ClientVethIPN     = ClientVethIP + "/24"
	ClientVethPeer    = ServerVethName
	ClientDeviceName  = "clt0"
	ClientWireGuardIP = "10.10.10.2"

	ServerHTTPPort  = "18888"
	NsNameExtension = "-ns"
)

var (
	// go test -v ./... -args -live
	flagLive = flag.Bool("live", false, "Run live tests on host")
)

type NetworkPeer struct {
	ns   *netns.NsHandle
	veth *netlink.Link
	name string
}

func (p *NetworkPeer) Set() error {
	return netns.Set(*p.ns)
}

func (p *NetworkPeer) Clean() {
	if p.ns != nil {
		p.Set()
		if p.veth != nil {
			netlink.LinkDel(*p.veth)
		}
		if p.ns != nil {
			netns.DeleteNamed(p.name)
			p.ns.Close()
		}
	}
}

func (p *NetworkPeer) Ns() *netns.NsHandle {
	return p.ns
}

type Network struct {
	PeerA *NetworkPeer
	PeerB *NetworkPeer
}

func NewNetwork(nameA, vethIPA, nameB, vethIPB string) (*Network, error) {
	hostns, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("netns.Get: %v", err)
	}

	n := &Network{&NetworkPeer{}, &NetworkPeer{}}
	retErr := func(strfmt string, a ...any) error {
		n.Clean()
		return fmt.Errorf(strfmt, a)
	}
	ns1, err := netns.NewNamed(nameA + NsNameExtension)
	if err != nil {
		return nil, retErr("netns.NewNamed(A): %v", err)
	}
	n.PeerA.ns = &ns1
	n.PeerA.name = nameA + NsNameExtension

	ns2, err := netns.NewNamed(nameB + NsNameExtension)
	if err != nil {
		return nil, retErr("netns.NewNamed(B): %v", err)
	}
	n.PeerB.ns = &ns2
	n.PeerB.name = nameB + NsNameExtension
	netns.Set(hostns)

	la := netlink.NewLinkAttrs()
	la.Name = nameA
	veth := &netlink.Veth{LinkAttrs: la, PeerName: nameB}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, retErr("netlink.LinkAdd(%s): %v", la.Name, err)
	}

	veth1, err := netlink.LinkByName(nameA)
	if err != nil {
		return nil, retErr("netlink.LinkByName(%s): %v", nameA, err)
	}
	n.PeerA.veth = &veth1
	if err := netlink.LinkSetNsFd(veth1, int(ns1)); err != nil {
		return nil, retErr("netlink.LinkSetNsFd(%v): %v", veth1, err)
	}

	veth2, err := netlink.LinkByName(nameB)
	if err != nil {
		return nil, retErr("netlink.LinkByName(%s): %v", nameB, err)
	}
	n.PeerB.veth = &veth2
	if err := netlink.LinkSetNsFd(veth2, int(ns2)); err != nil {
		return nil, retErr("netlink.LinkSetNsFd(%v): %v", veth2, err)
	}

	if err := setupNet(nameA, vethIPA, ns1); err != nil {
		return nil, retErr("setupNet(%s): %v", nameA, err)
	}
	if err := setupNet(nameB, vethIPB, ns2); err != nil {
		return nil, retErr("setupNet(%s): %v", nameB, err)
	}

	return n, nil
}

func (n *Network) Clean() {
	n.PeerA.Clean()
	n.PeerB.Clean()
}

func setupNet(name, cidr string, ns netns.NsHandle) error {
	hostns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("netns.Get: %v", err)
	}
	defer netns.Set(hostns)

	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("netns.Set: %v", err)
	}

	veth, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("netlink.LinkByName %s: %v", name, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("netlink.ParseAddr: %v", err)
	}

	if err := netlink.AddrAdd(veth, addr); err != nil {
		return fmt.Errorf("netlink.AddrAdd: %v", err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("netlink.LinkSetUp: %v", err)
	}

	return nil
}

func setupDevice(name, ip string) (*netlink.Wireguard, error) {
	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.Wireguard{LinkAttrs: la}
	addr, err := netlink.ParseAddr(ip)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return nil, err
	}
	return link, nil
}

type WgPeer struct {
	Name   string
	Key    wgtypes.Key
	Config wgtypes.Config
	Device *netlink.Wireguard
	Ctrl   *wgctrl.Client
}

func NewWgPeer(name, ip string, key wgtypes.Key, port *int) (*WgPeer, error) {
	config := wgtypes.Config{
		PrivateKey: &key,
	}
	if port != nil {
		config.ListenPort = port
	}

	dev, err := setupDevice(name, ip+"/24")
	if err != nil {
		return nil, err
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	return &WgPeer{
		Name:   name,
		Key:    key,
		Config: config,
		Device: dev,
		Ctrl:   client,
	}, nil
}

func (wp *WgPeer) AddPeer(cidr string, pubKey wgtypes.Key, endpoint *net.UDPAddr) error {
	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	peerConfig := wgtypes.PeerConfig{
		PublicKey:  pubKey,
		AllowedIPs: []net.IPNet{*ipn},
	}
	if endpoint != nil {
		peerConfig.Endpoint = endpoint
	}
	wp.Config.Peers = append(wp.Config.Peers, peerConfig)
	return nil
}

func (wp *WgPeer) Up() error {
	if err := wp.Ctrl.ConfigureDevice(wp.Name, wp.Config); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(wp.Device); err != nil {
		return err
	}
	return nil
}

func (wp *WgPeer) Down() error {
	return netlink.LinkSetDown(wp.Device)
}

func (wp *WgPeer) Cleanup() {
	wp.Down()
	wp.Ctrl.Close()
}

func startHTTP(p *NetworkPeer, srv *http.Server) {
	p.Set()
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		p.Set()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("failed to read body", "addr", r.RemoteAddr, "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("error reading body: %v", err)))
			return
		}
		slog.Info("received http request", "addr", r.RemoteAddr, "body", string(body))

		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})
	srv.ListenAndServe()
}

func addNftablesLogRule(group uint16, ns int) error {
	c, err := nftables.New(nftables.WithNetNSFd(ns))
	if err != nil {
		return err
	}

	filter := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	})
	input := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    filter,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	// nft add rule inet filter input udp dport 3000 log group 0
	key := uint32((1 << unix.NFTA_LOG_GROUP) | (1 << unix.NFTA_LOG_QTHRESHOLD) | (1 << unix.NFTA_LOG_SNAPLEN))
	c.AddRule(&nftables.Rule{
		Table: filter,
		Chain: input,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 0x00000011 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			// [ payload load 2b @ transport header + 2 => reg 1 ]
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			// [ cmp eq reg 1 0x0000b80b ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(ServerWireGuardPort)},
			// [ log group 0 snaplen 0 qthreshold 0 ]
			&expr.Log{Key: key, Group: group, Snaplen: 65535},
		},
	})

	if err := c.Flush(); err != nil {
		return err
	}

	return nil
}

func run(n *Network, mType string, ckey, skey wgtypes.Key) error {
	// nsenter veth1
	if err := n.PeerA.Set(); err != nil {
		return fmt.Errorf("failed to nsenter server net: %v", err)
	}

	// create wg server intf
	port := ServerWireGuardPort
	server, err := NewWgPeer(ServerDeviceName, ServerWireGuardIP, skey, &port)
	if err != nil {
		return fmt.Errorf("failed creating server peer: %v", err)
	}
	// start http hook mock
	srv := &http.Server{Addr: fmt.Sprintf(":%s", ServerHTTPPort)}
	go startHTTP(n.PeerA, srv)

	// setup wg interface and listener
	server.AddPeer(ClientWireGuardIP+"/24", ckey.PublicKey(), nil)
	if err := server.Up(); err != nil {
		return fmt.Errorf("failed starting srv: %v", err)
	}

	// set check params and init tracker
	idleTimeout = 2 * time.Second
	tickInterval = 1 * time.Second
	var monitor network.Monitor
	switch mType {
	case "nflog":
		group := uint16(0)
		ns := int(*n.PeerA.Ns())
		addNftablesLogRule(group, ns)
		monitor = network.NewNFLogMonitor(group, ns)
	default:
		monitor = network.NewBPFMonitor(ServerVethName, fmt.Sprintf("udp and dst port %d", ServerWireGuardPort))
	}
	tracker, err := NewTracker(monitor, fmt.Sprintf("http://%s:%s/echo", ServerWireGuardIP, ServerHTTPPort))
	if err != nil {
		return fmt.Errorf("failed to init tracker: %v", err)
	}

	// nsenter veth2
	if err := n.PeerB.Set(); err != nil {
		return fmt.Errorf("failed to nsenter client net: %v", err)
	}

	// create wg client intf
	client, err := NewWgPeer(ClientDeviceName, ClientWireGuardIP, ckey, nil)
	if err != nil {
		return fmt.Errorf("failed creating client peer: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ServerVethIP, ServerWireGuardPort))
	if err != nil {
		return fmt.Errorf("failed resolving udp addr: %v", err)
	}
	client.AddPeer(ServerWireGuardIP+"/24", skey.PublicKey(), addr)

	go func() {
		// start watch under veth0
		n.PeerA.Set()
		tracker.startWatch(func() {
			n.PeerA.Set()
			tracker.monitor.Watch()
		})
	}()
	time.Sleep(1 * time.Second)

	// init wg tunnel
	if err := client.Up(); err != nil {
		return fmt.Errorf("failed starting clt: %v", err)
	}

	// provoke traffic over wg tunnel
	makeRequest := func() {
		n.PeerB.Set()
		h := &http.Client{Timeout: 2 * time.Second}
		h.Get(fmt.Sprintf("http://%s:%s/echo", ServerWireGuardIP, ServerHTTPPort))
	}
	for range 3 {
		go makeRequest()
	}
	time.Sleep(2 * time.Second)

	// check live peers
	counter := func() int32 {
		var connCount atomic.Int32
		tracker.connMap.Range(func(k, v any) bool {
			connCount.Add(1)
			return true
		})
		return connCount.Load()
	}
	if got, want := counter(), int32(1); got != want {
		return fmt.Errorf("unexpected first conn count: got %d, want %d", got, want)
	}

	// disconnect wg tunnel
	if err := client.Down(); err != nil {
		return fmt.Errorf("failed shutting client dev: %v", err)
	}
	time.Sleep(3 * time.Second)

	// check live peers
	if got, want := counter(), int32(0); got != want {
		return fmt.Errorf("unexpected second conn count: got %d, want %d", got, want)
	}

	// shutdown http
	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownRelease()
	srv.Shutdown(shutdownCtx)
	http.DefaultServeMux = http.NewServeMux()
	return nil
}

func TestTracker(t *testing.T) {
	if !*flagLive {
		t.SkipNow()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed generating server key: %v", err)
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed generating client key: %v", err)
	}

	for _, mType := range []string{"nflog", "bpf"} {
		n, err := NewNetwork(ServerVethName, ServerVethIPN, ClientVethName, ClientVethIPN)
		if err != nil {
			t.Fatalf("failed creating network: %v", err)
		}

		slog.Info("initiating test", "monitor", mType)
		err = run(n, mType, clientKey, serverKey)
		n.Clean()
		if err != nil {
			t.Fatalf("test %s failed with error: %v", mType, err)
		}
	}
}
