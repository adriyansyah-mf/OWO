// Package edr remote output (Wazuh-style manager).
package edr

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// RemoteOutput sends alert records to a remote manager (TCP or HTTP).
type RemoteOutput struct {
	address    string
	protocol   string
	httpEndpoint string
	maxRetries int
	retryInterval time.Duration
	agentName  string
	agentHost  string
	agentGroup string
	mu         sync.Mutex
	client     *http.Client
}

// NewRemoteOutput creates a remote output. Call Send() for each alert.
func NewRemoteOutput(address, protocol, httpEndpoint string, maxRetries, retryIntervalSec int, agentName, agentHost, agentGroup string) *RemoteOutput {
	if protocol == "" {
		protocol = "tcp"
	}
	if maxRetries <= 0 {
		maxRetries = 5
	}
	if retryIntervalSec <= 0 {
		retryIntervalSec = 10
	}
	return &RemoteOutput{
		address:         address,
		protocol:        protocol,
		httpEndpoint:    httpEndpoint,
		maxRetries:      maxRetries,
		retryInterval:   time.Duration(retryIntervalSec) * time.Second,
		agentName:       agentName,
		agentHost:       agentHost,
		agentGroup:      agentGroup,
		client:          &http.Client{Timeout: 15 * time.Second},
	}
}

// Envelope wraps an alert with agent identity (for manager to know source).
type Envelope struct {
	AgentName  string      `json:"agent_name"`
	AgentHost  string      `json:"agent_hostname"`
	AgentGroup string      `json:"agent_group,omitempty"`
	Alert      interface{} `json:"alert"`
}

// Send delivers one alert record to the remote manager. Retries on failure. ctx can be nil for background.
func (r *RemoteOutput) Send(ctx context.Context, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	env := Envelope{
		AgentName:  r.agentName,
		AgentHost:  r.agentHost,
		AgentGroup: r.agentGroup,
		Alert:      json.RawMessage(payload),
	}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	body = append(body, '\n')

	var lastErr error
	for attempt := 0; attempt < r.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(r.retryInterval):
			}
		}
		switch r.protocol {
		case "tcp":
			lastErr = r.sendTCP(ctx, body, false)
		case "tls":
			lastErr = r.sendTCP(ctx, body, true)
		case "http", "https":
			lastErr = r.sendHTTP(ctx, body)
		default:
			lastErr = r.sendTCP(ctx, body, false)
		}
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("remote send after %d retries: %w", r.maxRetries, lastErr)
}

func (r *RemoteOutput) sendTCP(ctx context.Context, body []byte, useTLS bool) error {
	dialer := net.Dialer{}
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(&dialer, "tcp", r.address, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", r.address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	_, err = conn.Write(body)
	return err
}

func (r *RemoteOutput) sendHTTP(ctx context.Context, body []byte) error {
	scheme := "http"
	if r.protocol == "https" {
		scheme = "https"
	}
	url := scheme + "://" + r.address + r.httpEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Name", r.agentName)
	req.Header.Set("X-Agent-Hostname", r.agentHost)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("remote returned %s", resp.Status)
	}
	return nil
}
