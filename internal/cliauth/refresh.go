package cliauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Refresh exchanges the stored refresh token for a new access token.
//
// GoTrue may rotate the refresh token on every call; the returned [Credentials]
// must be saved even when only the access token changed.
func Refresh(ctx context.Context, creds Credentials) (Session, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return Session{}, err
	}
	if creds.RefreshToken == "" {
		return Session{}, ErrNotLoggedIn
	}

	endpoint := cfg.SupabaseURL + "/auth/v1/token?grant_type=refresh_token"
	body, err := json.Marshal(map[string]string{
		"refresh_token": creds.RefreshToken,
	})
	if err != nil {
		return Session{}, err
	}

	resp, err := postToken(ctx, cfg, endpoint, body)
	if err != nil {
		return Session{}, fmt.Errorf("refreshing session: %w", err)
	}

	updated := creds
	if resp.RefreshToken != "" {
		updated.RefreshToken = resp.RefreshToken
	}
	if resp.User.ID != "" {
		updated.UserID = resp.User.ID
	}
	if resp.User.Email != "" {
		updated.Email = resp.User.Email
	}
	updated.SavedAt = time.Now().UTC()

	return Session{AccessToken: resp.AccessToken, Credentials: updated}, nil
}

// AccessToken returns a valid access token, refreshing and persisting when needed.
func AccessToken(ctx context.Context) (string, Credentials, error) {
	creds, err := Load()
	if err != nil {
		return "", Credentials{}, err
	}

	session, err := Refresh(ctx, creds)
	if err != nil {
		return "", Credentials{}, err
	}

	if err := Save(session.Credentials); err != nil {
		return "", Credentials{}, err
	}
	return session.AccessToken, session.Credentials, nil
}
