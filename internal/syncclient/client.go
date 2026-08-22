// Package syncclient pushes local scan history to the product API.
package syncclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 32 << 20 // match server maxSyncBody

// RefreshFunc mints a new access token when the current one expired.
type RefreshFunc func(ctx context.Context) (token string, err error)

// Client talks to /api/v1/sync on the product server.
type Client struct {
	BaseURL string
	Token   string
	Refresh RefreshFunc
	HTTP    *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

type apiError struct {
	Error string `json:"error"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	return c.doRetry(ctx, method, path, body, out, true)
}

func (c *Client) doRetry(ctx context.Context, method, path string, body any, out any, allowRefresh bool) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	url := strings.TrimRight(c.BaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized && allowRefresh && c.Refresh != nil {
		token, refreshErr := c.Refresh(ctx)
		if refreshErr != nil {
			return fmt.Errorf("session expired: %w", refreshErr)
		}
		c.Token = token
		return c.doRetry(ctx, method, path, body, out, false)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var ae apiError
		_ = json.Unmarshal(raw, &ae)
		msg := ae.Error
		if msg == "" {
			msg = string(raw)
		}
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, msg)
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// PutRepoRequest upserts CLI repo metadata.
type PutRepoRequest struct {
	Name        string   `json:"name"`
	Origin      string   `json:"origin"`
	Path        string   `json:"path"`
	FormerPaths []string `json:"formerPaths,omitempty"`
	LastRunID   string   `json:"lastRunId"`
}

// PutRepo upserts a repo link for the CLI client repo id.
func (c *Client) PutRepo(ctx context.Context, clientRepoID string, req PutRepoRequest) error {
	path := fmt.Sprintf("/api/v1/sync/repos/%s", urlPath(clientRepoID))
	return c.do(ctx, http.MethodPut, path, req, nil)
}

// ScanSummary records one scanner in a run payload.
type ScanSummary struct {
	Scanner    string `json:"scanner"`
	Findings   int    `json:"findings"`
	DurationMS int64  `json:"durationMs,omitempty"`
	Error      string `json:"error,omitempty"`
}

// RunVCS is version-control metadata.
type RunVCS struct {
	Origin string `json:"origin,omitempty"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// Counts tallies findings.
type Counts struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity,omitempty"`
	ByCategory map[string]int `json:"byCategory,omitempty"`
}

// DeltaCounts summarizes lifecycle changes.
type DeltaCounts struct {
	New       int `json:"new"`
	StillOpen int `json:"stillOpen"`
	Fixed     int `json:"fixed"`
	Regressed int `json:"regressed"`
}

// Finding is one normalized finding row for sync.
type Finding struct {
	Fingerprint       string          `json:"fingerprint"`
	Scanner           string          `json:"scanner,omitempty"`
	Scanners          []string        `json:"scanners,omitempty"`
	RuleID            string          `json:"ruleId,omitempty"`
	Aliases           []string        `json:"aliases,omitempty"`
	Category          string          `json:"category,omitempty"`
	Severity          string          `json:"severity,omitempty"`
	Title             string          `json:"title,omitempty"`
	Message           string          `json:"message,omitempty"`
	LocationPath      string          `json:"locationPath,omitempty"`
	LocationStartLine int             `json:"locationStartLine,omitempty"`
	LocationEndLine   int             `json:"locationEndLine,omitempty"`
	LocationSnippet   string          `json:"locationSnippet,omitempty"`
	PackageName       string          `json:"packageName,omitempty"`
	PackageVersion    string          `json:"packageVersion,omitempty"`
	PackageEcosystem  string          `json:"packageEcosystem,omitempty"`
	PackagePURL       string          `json:"packagePurl,omitempty"`
	FixedIn           string          `json:"fixedIn,omitempty"`
	Refs              json.RawMessage `json:"refs,omitempty"`
	Status            string          `json:"status,omitempty"`
}

// PutRunRequest upserts one run and its findings.
type PutRunRequest struct {
	PrevRunID   string          `json:"prevRunId"`
	StartedAt   time.Time       `json:"startedAt"`
	FinishedAt  time.Time       `json:"finishedAt"`
	DurationMS  int64           `json:"durationMs"`
	ToolName    string          `json:"toolName"`
	ToolVersion string          `json:"toolVersion"`
	VCS         RunVCS          `json:"vcs"`
	Scanners    []ScanSummary   `json:"scanners"`
	ScopeHash   string          `json:"scopeHash"`
	Counts      Counts          `json:"counts"`
	Delta       DeltaCounts     `json:"delta"`
	Unreadable  bool            `json:"unreadable"`
	Problem     string          `json:"problem"`
	Document    json.RawMessage `json:"document"`
	Findings    []Finding       `json:"findings"`
}

// PutRun upserts one run for a CLI client repo id.
func (c *Client) PutRun(ctx context.Context, clientRepoID, clientRunID string, req PutRunRequest) error {
	path := fmt.Sprintf("/api/v1/sync/repos/%s/runs/%s", urlPath(clientRepoID), urlPath(clientRunID))
	return c.do(ctx, http.MethodPut, path, req, nil)
}

// FindingState is one lifecycle index entry.
type FindingState struct {
	Fingerprint string    `json:"fingerprint"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity,omitempty"`
	Category    string    `json:"category,omitempty"`
	Title       string    `json:"title,omitempty"`
	Scanners    []string  `json:"scanners,omitempty"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	FirstRun    string    `json:"firstRun,omitempty"`
	LastRun     string    `json:"lastRun,omitempty"`
	FixedAt     time.Time `json:"fixedAt,omitempty"`
	FixedRun    string    `json:"fixedRun,omitempty"`
	Occurrences int       `json:"occurrences"`
	Regressions int       `json:"regressions"`
}

// PutStates replaces the lifecycle index for a repo.
func (c *Client) PutStates(ctx context.Context, clientRepoID string, states []FindingState) error {
	if states == nil {
		states = []FindingState{}
	}
	path := fmt.Sprintf("/api/v1/sync/repos/%s/states", urlPath(clientRepoID))
	return c.do(ctx, http.MethodPut, path, states, nil)
}

func urlPath(s string) string {
	return url.PathEscape(s)
}
