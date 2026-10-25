package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	base string
	auth string
	http *http.Client
}

// newClient требует https, кроме явного loopback (для локальной отладки).
func newClient(server, caFile, hostID, hostKey string) (*Client, error) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("некорректный адрес сервера: %q", server)
	}
	host, _, _ := net.SplitHostPort(u.Host)
	if host == "" {
		host = u.Host
	}
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, errors.New("сервер должен быть доступен по https (http допустим только для localhost)")
	}
	tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 15 * time.Second}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file: нет сертификатов в файле")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := &Client{base: strings.TrimRight(server, "/"), http: &http.Client{Transport: tr}}
	if hostID != "" {
		c.auth = "Bearer " + hostID + "." + hostKey
	}
	return c, nil
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.auth != "" {
		req.Header.Set("Authorization", c.auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return &httpError{resp.StatusCode, strings.TrimSpace(string(data))}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.body) }

type Command struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	SID  string `json:"sid,omitempty"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

func (c *Client) poll(ctx context.Context) ([]Command, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var r struct {
		Commands []Command `json:"commands"`
	}
	err := c.post(ctx, "/agent/poll", map[string]any{}, &r)
	return r.Commands, err
}

func (c *Client) reportPosture(ctx context.Context, p Posture, osName string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.post(ctx, "/agent/report", map[string]any{"kind": "posture", "data": p, "version": version, "os": osName}, nil)
}

func (c *Client) reportMetrics(ctx context.Context, m Metrics) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return c.post(ctx, "/agent/report", map[string]any{"kind": "metrics", "data": m}, nil)
}

func (c *Client) reportSoftware(ctx context.Context, items []SoftwareItem) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return c.post(ctx, "/agent/report", map[string]any{"kind": "software", "data": items}, nil)
}

func (c *Client) reportTerm(ctx context.Context, sid string, seq int, data []byte, errMsg string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	m := map[string]any{"sid": sid, "seq": seq}
	if len(data) > 0 {
		m["data"] = b64(data)
	}
	if errMsg != "" {
		m["error"] = errMsg
	}
	return c.post(ctx, "/agent/term", m, nil)
}

func (c *Client) reportTermExit(ctx context.Context, sid string, code int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.post(ctx, "/agent/term", map[string]any{"sid": sid, "exit": true, "code": code}, nil)
}
