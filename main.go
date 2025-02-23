package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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
	interfacePtr := flagStringEnvOverride("interface", "eth0", "interface where to listen for packets")
	filterPtr := flagStringEnvOverride("filter", "udp and dst port 3000", "bpf filter triggering wg show")
	webhookPtr := flagStringEnvOverride("webhook", "", "custom webhook where to report events")
	flag.Parse()

	tracker, err := wg.NewTracker(*interfacePtr, *webhookPtr, *filterPtr)
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
