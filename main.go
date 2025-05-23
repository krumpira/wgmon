package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/turekt/wgmon/network"
	"github.com/turekt/wgmon/wg"
)

func flagStringEnvOverride(key, value, desc string) *string {
	ptr := flag.String(key, value, desc)
	if e := os.Getenv(key); e != "" {
		*ptr = e
	}
	return ptr
}

func main() {
	monitorTypePtr := flagStringEnvOverride("monitor", "nflog", "type of monitor to use (bpf or nflog)")
	groupPtr := flagStringEnvOverride("group", "1", "nflog group index in case nflog is used as monitor")
	interfacePtr := flagStringEnvOverride("interface", "eth0", "interface where to listen for packets (if bpf is used)")
	filterPtr := flagStringEnvOverride("filter", "udp and dst port 3000", "bpf filter triggering wg show (if bpf is used)")
	webhookPtr := flagStringEnvOverride("webhook", "", "custom webhook where to report events")
	flag.Parse()

	var monitor network.Monitor
	switch *monitorTypePtr {
	case "bpf":
		monitor = network.NewBPFMonitor(*interfacePtr, *filterPtr)
	default:
		group, err := strconv.ParseUint(*groupPtr, 10, 16)
		if err != nil {
			slog.Error("unable to parse provided group to uint16", "provided", *groupPtr, "error", err)
		}
		monitor = network.NewNFLogMonitor(uint16(group), 0)
	}

	tracker, err := wg.NewTracker(monitor, *webhookPtr)
	if err != nil {
		slog.Error("failed to initiate tracker", "error", err)
		return
	}
	tracker.Start()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-sigc
	tracker.Stop()
}
