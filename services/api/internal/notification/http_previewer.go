package notification

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/propagation"
)

const (
	notificationPreviewPath        = "/internal/v1/notification-preview"
	notificationSMTPHealthPath     = "/internal/v1/smtp-health"
	maximumNotificationPreviewBody = 512 * 1024
	maximumSMTPHealthBody          = 16 * 1024
)

var notificationPreviewTemplateID = uuid.MustParse("01900000-0000-7000-8000-000000000001")

// HTTPPreviewer is the narrow API-to-notifier rendering boundary. It disables
// environment proxies and redirects so the internal bearer token cannot be
// forwarded outside the configured notifier origin.
type HTTPPreviewer struct {
	previewEndpoint    *url.URL
	smtpHealthEndpoint *url.URL
	token              []byte
	client             *http.Client
	mu                 sync.RWMutex
	closed             bool
}

func NewHTTPPreviewer(baseURL string, token []byte, timeout time.Duration) (*HTTPPreviewer, error) {
	previewEndpoint, err := canonicalNotifierURL(baseURL, notificationPreviewPath)
	if err != nil || !validPreviewToken(token) || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, ErrInvalidInput
	}
	smtpHealthEndpoint, err := canonicalNotifierURL(baseURL, notificationSMTPHealthPath)
	if err != nil {
		return nil, ErrInvalidInput
	}
	secret := append([]byte(nil), token...)
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &HTTPPreviewer{
		previewEndpoint:    previewEndpoint,
		smtpHealthEndpoint: smtpHealthEndpoint,
		token:              secret,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (p *HTTPPreviewer) Preview(
	ctx context.Context,
	tenantID uuid.UUID,
	audience Audience,
	fields TemplateFields,
	contextData map[string]any,
) (Preview, error) {
	if ctx == nil || !validUUIDv7(tenantID) {
		return Preview{}, ErrInvalidInput
	}
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return Preview{}, ErrUnavailable
	}
	token := append([]byte(nil), p.token...)
	endpoint := p.previewEndpoint.String()
	p.mu.RUnlock()
	defer clear(token)
	payload := struct {
		Audience Audience        `json:"audience"`
		Template previewTemplate `json:"template"`
		Context  map[string]any  `json:"context"`
	}{
		Audience: audience,
		Template: previewTemplate{
			ID: notificationPreviewTemplateID, TenantID: tenantID, Version: 1,
			Key: fields.Key, Name: fields.Name, Language: fields.Language,
			Subject: fields.Subject, HTML: fields.HTML, PlainText: fields.PlainText, CSS: fields.CSS,
		},
		Context: contextData,
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumNotificationPreviewBody {
		clear(encoded)
		return Preview{}, ErrInvalidInput
	}
	defer clear(encoded)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return Preview{}, ErrUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Accept", "application/json")
	// Only the W3C trace-context fields are propagated. Baggage and arbitrary
	// inbound headers must never cross this secret-bearing internal boundary.
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(request.Header))
	response, err := p.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Preview{}, err
		}
		return Preview{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024))
		switch response.StatusCode {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
			return Preview{}, ErrInvalidInput
		case http.StatusTooManyRequests:
			return Preview{}, ErrRateLimited
		default:
			return Preview{}, ErrUnavailable
		}
	}
	if !isNotificationJSONResponse(response.Header.Get("Content-Type")) {
		return Preview{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumNotificationPreviewBody+1))
	if err != nil || len(body) == 0 || len(body) > maximumNotificationPreviewBody || !utf8.Valid(body) {
		clear(body)
		return Preview{}, ErrUnavailable
	}
	defer clear(body)
	var result struct {
		Subject   *string `json:"subject"`
		HTML      *string `json:"html"`
		PlainText *string `json:"plainText"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := rejectDuplicateJSONNames(body); err != nil {
		return Preview{}, ErrUnavailable
	}
	if err := decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		result.Subject == nil || result.HTML == nil || result.PlainText == nil {
		return Preview{}, ErrUnavailable
	}
	return Preview{Subject: *result.Subject, HTML: *result.HTML, PlainText: *result.PlainText}, nil
}

// ProbeSMTP performs a real notifier-side SMTP health check against one exact
// database-authorized configuration revision. The wire protocol carries only
// opaque identifiers and sanitized staged outcomes; provider configuration,
// secrets, destinations, and server banners never cross this boundary.
func (p *HTTPPreviewer) ProbeSMTP(ctx context.Context, input SMTPProbeRequest) (SMTPProbeResult, error) {
	if ctx == nil || !validSMTPProbeRequest(input) {
		return SMTPProbeResult{}, ErrInvalidInput
	}
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return SMTPProbeResult{}, ErrUnavailable
	}
	token := append([]byte(nil), p.token...)
	endpoint := p.smtpHealthEndpoint.String()
	p.mu.RUnlock()
	defer clear(token)

	payload := struct {
		ProbeID              uuid.UUID              `json:"probeId"`
		FenceToken           uuid.UUID              `json:"fenceToken"`
		TenantID             *uuid.UUID             `json:"tenantId,omitempty"`
		ConfigurationScope   SMTPConfigurationScope `json:"configurationScope"`
		ConfigurationID      uuid.UUID              `json:"configurationId"`
		ConfigurationVersion int64                  `json:"configurationVersion"`
	}{
		ProbeID: input.ProbeID, FenceToken: input.FenceToken,
		TenantID: cloneUUIDPointer(input.TenantID), ConfigurationScope: input.ConfigurationScope,
		ConfigurationID: input.ConfigurationID, ConfigurationVersion: input.ConfigurationVersion,
	}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSMTPHealthBody {
		clear(encoded)
		return SMTPProbeResult{}, ErrInvalidInput
	}
	defer clear(encoded)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return SMTPProbeResult{}, ErrUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Accept", "application/json")
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(request.Header))
	response, err := p.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return SMTPProbeResult{}, err
		}
		return SMTPProbeResult{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4*1024))
		if response.StatusCode == http.StatusTooManyRequests {
			return SMTPProbeResult{}, ErrRateLimited
		}
		return SMTPProbeResult{}, ErrUnavailable
	}
	if !isNotificationJSONResponse(response.Header.Get("Content-Type")) {
		return SMTPProbeResult{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumSMTPHealthBody+1))
	if err != nil || len(body) == 0 || len(body) > maximumSMTPHealthBody || !utf8.Valid(body) {
		clear(body)
		return SMTPProbeResult{}, ErrUnavailable
	}
	defer clear(body)
	if err := rejectDuplicateJSONNames(body); err != nil {
		return SMTPProbeResult{}, ErrUnavailable
	}
	var wire struct {
		ProbeID              *uuid.UUID              `json:"probeId"`
		FenceToken           *uuid.UUID              `json:"fenceToken"`
		TenantID             *uuid.UUID              `json:"tenantId"`
		ConfigurationScope   *SMTPConfigurationScope `json:"configurationScope"`
		ConfigurationID      *uuid.UUID              `json:"configurationId"`
		ConfigurationVersion *int64                  `json:"configurationVersion"`
		Healthy              *bool                   `json:"healthy"`
		CheckedAt            *time.Time              `json:"checkedAt"`
		Checks               *[]SMTPHealthCheck      `json:"checks"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		wire.ProbeID == nil || wire.FenceToken == nil || wire.ConfigurationScope == nil ||
		wire.ConfigurationID == nil || wire.ConfigurationVersion == nil || wire.Healthy == nil ||
		wire.CheckedAt == nil || wire.Checks == nil {
		return SMTPProbeResult{}, ErrUnavailable
	}
	return SMTPProbeResult{
		SMTPProbeRequest: SMTPProbeRequest{
			ProbeID: *wire.ProbeID, FenceToken: *wire.FenceToken,
			TenantID: cloneUUIDPointer(wire.TenantID), ConfigurationScope: *wire.ConfigurationScope,
			ConfigurationID: *wire.ConfigurationID, ConfigurationVersion: *wire.ConfigurationVersion,
		},
		Healthy: *wire.Healthy, CheckedAt: wire.CheckedAt.UTC(),
		Checks: append([]SMTPHealthCheck(nil), (*wire.Checks)...),
	}, nil
}

func (p *HTTPPreviewer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	clear(p.token)
	p.token = nil
	p.client.CloseIdleConnections()
}

type previewTemplate struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenantId"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Language  string    `json:"language"`
	Version   int64     `json:"version"`
	Subject   string    `json:"subject"`
	HTML      string    `json:"html"`
	PlainText *string   `json:"plainText,omitempty"`
	CSS       *string   `json:"css,omitempty"`
}

func canonicalNotifierURL(input, path string) (*url.URL, error) {
	if len(input) < 1 || len(input) > 2_048 || strings.TrimSpace(input) != input || strings.ContainsAny(input, "\x00\r\n\t") {
		return nil, ErrInvalidInput
	}
	parsed, err := url.Parse(input)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, ErrInvalidInput
	}
	parsed.Path = path
	parsed.RawPath = ""
	return parsed, nil
}

func validSMTPProbeRequest(input SMTPProbeRequest) bool {
	if !validUUIDv7(input.ProbeID) || !validUUIDv7(input.FenceToken) ||
		!validUUIDv7(input.ConfigurationID) || input.ConfigurationVersion < 1 ||
		input.ConfigurationVersion > maximumResourceVersion {
		return false
	}
	switch input.ConfigurationScope {
	case SMTPConfigurationTenant:
		return input.TenantID != nil && validUUIDv7(*input.TenantID)
	case SMTPConfigurationPlatform:
		return input.TenantID == nil || validUUIDv7(*input.TenantID)
	default:
		return false
	}
}

func cloneUUIDPointer(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validPreviewToken(value []byte) bool {
	if len(value) < 32 || len(value) > 512 {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) || unicode.IsControl(character) ||
			!(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') &&
				!(character >= '0' && character <= '9') && !strings.ContainsRune("._~+/=-", character) {
			return false
		}
	}
	return true
}

func isNotificationJSONResponse(value string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return mediaType == "application/json"
}
