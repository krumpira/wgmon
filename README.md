# Wireguard connection monitor

Wireguard connection monitor listens and reports newly connected wireguard peers via webhook.

## Project

There are existing Wireguard connection monitors available and they all use a similar approach to monitoring connections.

This repo tries to optimize the monitoring process and do things a bit differently:
- Monitor only when a connection is triggered, instead of constantly running `wg show`
  - utilizes nflog or gopacket bpf filter that triggers checks only on received packet
- Scan for currently connected peers by interacting directly with kernel
  - utilizes netlink to get info on wireguard links instead of executing `wg show all dump` on operating system level
- Recognize when peer has disconnected
  - after peer connects, initiate ticker that checks connection info and, if packets were not received for some time, register as a disconnect
  - the gap between actual disconnect and recognition can be optimized with usage of `PersistentKeepAlive` and smaller tick period

All this is paired with minimal dependencies needed to run things smoothly.

## Usage

The project is provided and intended to be ran within a container, therefore Docker or Podman installed is the only requirement.
```
# Podman
podman build -t wg .
# Docker
docker build -t wg .
# For specific wireguard interface name
docker build --build-arg intfname=custom -t wg .
```

Wireguard keys and config should be stored in `/etc/wireguard` on host. Project assumes listen port 3000, make sure to adapt project params per your config.

For Podman there is available kube file. Run the project with:
```
podman kube play kube.yaml
```

For Docker there is a docker compose file.
```
docker compose up
```

Project also runs locally.
```
go build -o app
sudo ./app
```

## Tests

To run tests:
```
# Skips live test
go test -v ./...
# Including live test
go test -v ./... -args -live
```

## Internals and how-to's

### Packet notification via Netfilter logging

Netfilter logging is used for packet notification by default (NFLogMonitor). This works by opening a unix socket via netlink library that listens on a specific group (group 1 set as default) for messages.
To properly utilize this feature there are two important components:
- wgmon configured to listen via nflog
- nftables or iptables that log packets via nflog to group

Here's an example on how to make this work. On nftables side (operating system level) execute:
```
nft create table inet filter
nft create chain inet filter input { type filter hook input priority 0 \; }
nft add rule inet filter input udp dport 3000 log group 1 snaplen 65535 prefix "Received packet on udp port 3000"
```

This rule instructs nftables to log UDP packets received on port 3000 to nflog group 1. All unix sockets bound to nflog group 1 will receive a packet once it hits port 3000. The firewall component can be easily covered with wireguard's `PostUp` options in configuration. Here's an example server configuration:
```
[Interface]
Address = 10.10.10.1/24
ListenPort = 3000
PrivateKey = <PRIVATE_KEY>
PostUp = nft add table inet wgmon
PostUp = nft add chain inet wgmon input { type filter hook input priority 0 \; policy drop \; }
PostUp = nft add rule inet wgmon input udp dport 3000 log group 1 snaplen 65535
PostUp = nft add rule inet wgmon input ct state established,related accept
PostUp = nft add rule inet wgmon input udp dport 3000 accept
PostDown = nft delete table inet wgmon

[Peer]
PublicKey = <PUBLIC_KEY>
AllowedIPs = 10.10.10.2/32
```

Small demonstration of the netfilter logging feature with simple log that writes packets in kernel log:
```
$ nft list ruleset
table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		tcp dport 8888 log prefix "Received packet on TCP 8888" snaplen 65535
	}
}
$ curl 127.0.0.1:8888
curl: (7) Failed to connect to 127.0.0.1 port 8888 after 0 ms: Couldn't connect to server
$ dmesg | tail -n 1
[116252.891085] Received packet on TCP 8888IN=lo OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=127.0.0.1 DST=127.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=34489 DF PROTO=TCP SPT=56672 DPT=8888 WINDOW=65495 RES=0x00 SYN URGP=0
```

This approach is not much different than firewall logging packets into a file. The difference is that, with `group`, all packets are sent directly to listening sockets removing the need for intermediate files or opening PCAP handles with filters to sniff traffic.

If wgmon is configured with `monitor=nflog` and `group=1` (both defaults), it will receive incoming packets which trigger tracking of wireguard connections.

### Packet notification via PCAP filtering

In case netfilter logging is not available, BPF can be used as fallback (BPFMonitor). This approach opens a PCAP handle with minimal filter to capture incoming packets which trigger tracking of wireguard connections.

In case of BPF filter, there are no additional components involved as everything is handled by wgmon, with a downside that live packet capture is usually considered heavier on resources.

For this to work wgmon must be configured with `monitor=bpf` and appropriate `interface` and `filter`. Use your public facing interface (`eth0` is set as default) and filter that captures only the wireguard listening port (`udp and dst port 3000` is set as default).