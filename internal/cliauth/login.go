package cliauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Provider names supported OAuth providers in Supabase GoTrue.
type Provider string

const (
	ProviderGitHub Provider = "github"
	ProviderGoogle Provider = "google"
)

// Valid reports whether p is a supported provider.
func (p Provider) Valid() bool {
	switch p {
	case ProviderGitHub, ProviderGoogle:
		return true
	default:
		return false
	}
}

const loginTimeout = 120 * time.Second

// Session is a short-lived access token plus refreshed credentials to persist.
type Session struct {
	AccessToken string
	Credentials Credentials
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	User         struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

type tokenErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Login runs browser OAuth with a localhost callback and PKCE.
//
// progress receives stage updates when non-nil; [internal/tui] implements the
// animated renderer, plain-text fallbacks live in the CLI.
func Login(ctx context.Context, provider Provider, progress LoginProgress) (Session, error) {
	if !provider.Valid() {
		return Session{}, fmt.Errorf("unsupported provider %q (want github or google)", provider)
	}

	report := func(stage LoginStage, detail string) {
		if progress != nil {
			progress(stage, detail)
		}
	}

	cfg, err := LoadConfig()
	if err != nil {
		return Session{}, err
	}

	pkce, err := newPKCEPair()
	if err != nil {
		return Session{}, err
	}

	loginCtx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	port, codeCh, errCh, cleanup, err := startCallbackServer(loginCtx)
	if err != nil {
		return Session{}, err
	}
	defer cleanup()

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	authURL, err := buildAuthorizeURL(cfg, provider, callbackURL, pkce.Challenge)
	if err != nil {
		return Session{}, err
	}

	if AutoOpenBrowser() {
		report(LoginStageOpeningBrowser, "")
		if err := openURL(authURL); err != nil {
			report(LoginStageManualURL, authURL)
		} else {
			report(LoginStageWaitingBrowser, "")
		}
	} else {
		report(LoginStageManualURL, authURL)
	}

	select {
	case <-loginCtx.Done():
		return Session{}, fmt.Errorf("login timed out after %s — try again", loginTimeout)
	case err := <-errCh:
		return Session{}, err
	case code := <-codeCh:
		report(LoginStageVerifying, "")
		session, err := exchangePKCE(loginCtx, cfg, code, pkce.Verifier, provider)
		if err != nil {
			return Session{}, err
		}
		return session, nil
	}
}

func buildAuthorizeURL(cfg Config, provider Provider, redirectTo, challenge string) (string, error) {
	base, err := url.Parse(cfg.SupabaseURL + "/auth/v1/authorize")
	if err != nil {
		return "", fmt.Errorf("parsing Supabase URL: %w", err)
	}

	q := base.Query()
	q.Set("provider", string(provider))
	q.Set("redirect_to", redirectTo)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	base.RawQuery = q.Encode()
	return base.String(), nil
}

func exchangePKCE(ctx context.Context, cfg Config, authCode, verifier string, provider Provider) (Session, error) {
	endpoint := cfg.SupabaseURL + "/auth/v1/token?grant_type=pkce"
	body, err := json.Marshal(map[string]string{
		"auth_code":     authCode,
		"code_verifier": verifier,
	})
	if err != nil {
		return Session{}, err
	}

	resp, err := postToken(ctx, cfg, endpoint, body)
	if err != nil {
		return Session{}, err
	}

	creds := Credentials{
		RefreshToken: resp.RefreshToken,
		UserID:       resp.User.ID,
		Email:        resp.User.Email,
		Provider:     provider,
		SavedAt:      time.Now().UTC(),
	}
	return Session{AccessToken: resp.AccessToken, Credentials: creds}, nil
}

func startCallbackServer(ctx context.Context) (port int, codeCh chan string, errCh chan error, cleanup func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("starting local callback server: %w", err)
	}

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return 0, nil, nil, nil, fmt.Errorf("unexpected listener address type")
	}

	codeCh = make(chan string, 1)
	errCh = make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			errCh <- fmt.Errorf("login failed: %s — %s", errMsg, desc)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, callbackErrorPage(errMsg, desc))
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("login callback missing authorization code")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, callbackErrorPage("missing_code", "No authorization code was returned."))
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, callbackSuccessPage())
		codeCh <- code
	})

	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- fmt.Errorf("callback server: %w", serveErr)
		}
	}()

	cleanup = func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}

	go func() {
		<-ctx.Done()
		cleanup()
	}()

	return tcpAddr.Port, codeCh, errCh, cleanup, nil
}

func postToken(ctx context.Context, cfg Config, endpoint string, body []byte) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", cfg.SupabaseAnonKey)
	req.Header.Set("Authorization", "Bearer "+cfg.SupabaseAnonKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("talking to Supabase: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var te tokenErrorBody
		_ = json.Unmarshal(raw, &te)
		msg := te.ErrorDescription
		if msg == "" {
			msg = te.Error
		}
		if msg == "" {
			msg = string(raw)
		}
		return tokenResponse{}, fmt.Errorf("Supabase rejected login (%d): %s", resp.StatusCode, msg)
	}

	var tr tokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return tokenResponse{}, fmt.Errorf("decoding token response: %w", err)
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		return tokenResponse{}, fmt.Errorf("Supabase returned an incomplete session")
	}
	return tr, nil
}
