package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoperations"
)

func TestDecodePlatformOperationsDocumentIsStrictAndBounded(t *testing.T) {
	valid := []byte(`{"projectionVersion":1,"items":[],"nextCursor":null}`)
	page, err := decodePlatformOperationsDocument[platformoperations.UserPage](valid)
	if err != nil || page.ProjectionVersion != 1 || len(page.Items) != 0 {
		t.Fatalf("page = %#v, error = %v", page, err)
	}
	for name, document := range map[string][]byte{
		"unknown field": []byte(`{"projectionVersion":1,"items":[],"nextCursor":null,"raw":true}`),
		"trailing":      []byte(`{"projectionVersion":1,"items":[],"nextCursor":null}{}`),
		"invalid":       []byte(`{"projectionVersion":`),
		"oversized":     make([]byte, maximumPlatformOperationsDocumentBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePlatformOperationsDocument[platformoperations.UserPage](document); err == nil {
				t.Fatal("malformed document was accepted")
			}
		})
	}
}

func TestMapPlatformGlobalSettingsPreservesNullableSupportURL(t *testing.T) {
	now := time.Date(2026, 9, 1, 20, 0, 0, 0, time.UTC)
	withoutURL, err := mapPlatformGlobalSettings("Periapsis", "en", "UTC", "", 1, now)
	if err != nil || withoutURL.SupportURL != nil {
		t.Fatalf("settings = %#v, error = %v", withoutURL, err)
	}
	withURL, err := mapPlatformGlobalSettings(
		"Periapsis", "it-IT", "Europe/Rome", "https://support.example.invalid", 2, now,
	)
	if err != nil || withURL.SupportURL == nil || *withURL.SupportURL != "https://support.example.invalid" {
		t.Fatalf("settings = %#v, error = %v", withURL, err)
	}
}

func TestMapPlatformOperationsDatabaseErrorsFailClosed(t *testing.T) {
	for code, want := range map[string]error{
		"22023": platformoperations.ErrInvalidInput,
		"42501": platformoperations.ErrForbidden,
		"P0002": platformoperations.ErrNotFound,
		"40001": platformoperations.ErrConflict,
	} {
		t.Run(code, func(t *testing.T) {
			got := mapPlatformOperationsDatabaseError(&pgconn.PgError{Code: code})
			if !errors.Is(got, want) {
				t.Fatalf("error = %v, want %v", got, want)
			}
		})
	}
}
