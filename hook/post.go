package hook

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/turekt/wgmon/network"
)

const (
	MessageStateFormat  = `Connection %s on endpoint %s is %s`
	MessagePacketFormat = `%s
%s
%s{%s} %s -> %s
`
)

func PostPacketDetails(webhookUrl string, p *network.PacketDetails) error {
	slog.Info("packet received", "packet", *p)
	if webhookUrl == "" {
		return nil
	}

	msg := fmt.Sprintf(
		MessagePacketFormat,
		p.Time.Format("2006-01-02 15:04:05 UTC"),
		"Received packet",
		p.L4Proto, p.L5Proto, p.RemoteAddr(), p.Destination(),
	)
	return Post(webhookUrl, msg)
}

func PostState(webhookUrl, endpoint, id, state string) error {
	slog.Info("client state change", "endpoint", endpoint, "id", id, "state", state)
	if webhookUrl == "" {
		return nil
	}

	return Post(webhookUrl, fmt.Sprintf(MessageStateFormat, id, endpoint, state))
}

func Post(webhookUrl, content string) error {
	slog.Info("webhook post", "webhook", webhookUrl, "content", content)
	formData := url.Values{
		"content": {content},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("POST", webhookUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("received status %d", resp.StatusCode)
	}

	return nil
}
