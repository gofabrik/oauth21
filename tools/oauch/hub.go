package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// recordSeparator ends every SignalR JSON frame.
const recordSeparator = "\x1e"

// SignalR message types.
const (
	invocationMessage = 1
	closeMessage      = 7
)

// message is a frame the hub sends.
type message struct {
	Type      int               `json:"type"`
	Target    string            `json:"target"`
	Arguments []json.RawMessage `json:"arguments"`
	Error     string            `json:"error"`
}

// hub is a SignalR connection to the test run hub of OAuch over long polling.
type hub struct {
	client *http.Client
	url    string
}

// dialHub connects to the test run hub of the OAuch at base and sends the handshake.
func dialHub(ctx context.Context, client *http.Client, base string) (*hub, error) {
	var negotiation struct {
		ConnectionToken string `json:"connectionToken"`
	}
	resp, err := do(ctx, client, http.MethodPost, base+"/testrunhub/negotiate?negotiateVersion=1", "", nil)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(resp, &negotiation)
	if err != nil || negotiation.ConnectionToken == "" {
		return nil, errors.Join(errors.New("negotiate: no connection token"), err)
	}
	h := &hub{client: client, url: base + "/testrunhub?id=" + url.QueryEscape(negotiation.ConnectionToken)}
	return h, h.send(ctx, `{"protocol":"json","version":1}`)
}

// invoke calls the hub method target with args without waiting for its result.
func (h *hub) invoke(ctx context.Context, target string, args ...string) error {
	frame, err := json.Marshal(struct {
		Type      int      `json:"type"`
		Target    string   `json:"target"`
		Arguments []string `json:"arguments"`
	}{invocationMessage, target, args})
	if err != nil {
		return err
	}
	return h.send(ctx, string(frame))
}

func (h *hub) send(ctx context.Context, frame string) error {
	_, err := do(ctx, h.client, http.MethodPost, h.url, "text/plain", strings.NewReader(frame+recordSeparator))
	return err
}

// poll waits for the next frames of the hub.
func (h *hub) poll(ctx context.Context) ([]message, error) {
	b, err := do(ctx, h.client, http.MethodGet, h.url, "", nil)
	if err != nil {
		return nil, err
	}
	return parseFrames(b)
}

// parseFrames parses the SignalR JSON frames in b.
func parseFrames(b []byte) ([]message, error) {
	var msgs []message
	for frame := range bytes.SplitSeq(b, []byte(recordSeparator)) {
		if len(bytes.TrimSpace(frame)) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(frame, &m); err != nil {
			return nil, fmt.Errorf("hub frame %q: %w", frame, err)
		}
		msgs = append(msgs, m)
	}
	return msgs, nil
}
