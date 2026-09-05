package notification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/trace"
)

func TestHTTPPreviewerSendsTenantScopedRequestAndReturnsPreview(t *testing.T) {
	tenantID := mustV7(t)
	token := []byte(strings.Repeat("a", 40))
	expectedToken := string(token)
	plainText := "Case {{case.number}}"
	css := "p { color: red; }"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != notificationPreviewPath || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s", request.Method, request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+expectedToken {
			t.Errorf("authorization = %q", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("content type = %q", got)
		}
		if got := request.Header.Get("Traceparent"); got != "00-11111111111111111111111111111111-2222222222222222-01" {
			t.Errorf("traceparent = %q", got)
		}
		if got := request.Header.Get("Tracestate"); got != "vendor=value" {
			t.Errorf("tracestate = %q", got)
		}
		if got := request.Header.Get("Baggage"); got != "" {
			t.Errorf("baggage crossed preview boundary = %q", got)
		}
		var payload struct {
			Audience Audience        `json:"audience"`
			Template previewTemplate `json:"template"`
			Context  map[string]any  `json:"context"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload.Audience != AudienceOperator || payload.Template.ID != notificationPreviewTemplateID ||
			payload.Template.TenantID != tenantID || payload.Template.Version != 1 ||
			payload.Template.Key != "case.updated" || payload.Template.PlainText == nil ||
			*payload.Template.PlainText != plainText || payload.Template.CSS == nil || *payload.Template.CSS != css {
			t.Errorf("payload = %#v", payload)
		}
		caseContext, ok := payload.Context["case"].(map[string]any)
		if !ok || caseContext["number"] != "CASE-1" {
			t.Errorf("context = %#v", payload.Context)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"subject":"Case CASE-1","html":"<p>CASE-1</p>","plainText":"CASE-1"}`))
	}))
	defer server.Close()

	previewer, err := NewHTTPPreviewer(server.URL, token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer previewer.Close()
	token[0] = 'z'
	traceID, err := trace.TraceIDFromHex("11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("2222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	traceState, err := trace.ParseTraceState("vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled, TraceState: traceState,
	}))
	member, err := baggage.NewMember("sensitive", "must-not-cross")
	if err != nil {
		t.Fatal(err)
	}
	bag, err := baggage.New(member)
	if err != nil {
		t.Fatal(err)
	}
	ctx = baggage.ContextWithBaggage(ctx, bag)

	preview, err := previewer.Preview(ctx, tenantID, AudienceOperator, TemplateFields{
		Key: "case.updated", Name: "Case updated", Language: "en", Subject: "Case {{case.number}}",
		HTML: "<p>{{case.number}}</p>", PlainText: &plainText, CSS: &css,
	}, map[string]any{"case": map[string]any{"number": "CASE-1"}})
	if err != nil || preview.Subject != "Case CASE-1" || preview.HTML != "<p>CASE-1</p>" || preview.PlainText != "CASE-1" {
		t.Fatalf("Preview() = %#v, %v", preview, err)
	}
}

func TestHTTPPreviewerDoesNotFollowRedirectOrForwardToken(t *testing.T) {
	var redirectedRequests atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", destination.URL+notificationPreviewPath)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	previewer, err := NewHTTPPreviewer(origin.URL, []byte(strings.Repeat("r", 40)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer previewer.Close()
	_, err = previewer.Preview(context.Background(), mustV7(t), AudienceOperator, serviceTemplateFields(), map[string]any{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Preview() error = %v", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirected requests = %d", got)
	}
}

func TestHTTPPreviewerProbesExactPinnedSMTPConfiguration(t *testing.T) {
	tenantID := mustV7(t)
	probeID := mustV7(t)
	fenceToken := mustV7(t)
	configurationID := mustV7(t)
	checkedAt := validInstantFixture()
	token := []byte(strings.Repeat("h", 40))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != notificationSMTPHealthPath || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s", request.Method, request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer "+string(token) {
			t.Errorf("authorization = %q", got)
		}
		var payload struct {
			ProbeID              string `json:"probeId"`
			FenceToken           string `json:"fenceToken"`
			TenantID             string `json:"tenantId"`
			ConfigurationScope   string `json:"configurationScope"`
			ConfigurationID      string `json:"configurationId"`
			ConfigurationVersion int64  `json:"configurationVersion"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload.ProbeID != probeID.String() || payload.FenceToken != fenceToken.String() ||
			payload.TenantID != tenantID.String() || payload.ConfigurationScope != "tenant" ||
			payload.ConfigurationID != configurationID.String() || payload.ConfigurationVersion != 7 {
			t.Errorf("payload = %#v", payload)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"probeId": probeID, "fenceToken": fenceToken, "tenantId": tenantID,
			"configurationScope": "tenant", "configurationId": configurationID,
			"configurationVersion": 7, "healthy": true, "checkedAt": checkedAt,
			"checks": []map[string]string{
				{"kind": "dns", "outcome": "passed"},
				{"kind": "connect", "outcome": "passed"},
				{"kind": "tls", "outcome": "passed"},
				{"kind": "authentication", "outcome": "passed"},
			},
		})
	}))
	defer server.Close()

	client, err := NewHTTPPreviewer(server.URL, token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.ProbeSMTP(context.Background(), SMTPProbeRequest{
		ProbeID: probeID, FenceToken: fenceToken, TenantID: &tenantID,
		ConfigurationScope: SMTPConfigurationTenant,
		ConfigurationID:    configurationID, ConfigurationVersion: 7,
	})
	if err != nil || !result.Healthy || !result.CheckedAt.Equal(checkedAt) || len(result.Checks) != 4 {
		t.Fatalf("ProbeSMTP() = %#v, %v", result, err)
	}
}

func TestHTTPPreviewerSMTPProbeResponseFailsClosed(t *testing.T) {
	probeID := mustV7(t)
	fenceToken := mustV7(t)
	configurationID := mustV7(t)
	tests := []struct {
		name string
		body string
	}{
		{
			name: "duplicate nested field",
			body: `{"probeId":"` + probeID.String() + `","fenceToken":"` + fenceToken.String() +
				`","configurationScope":"platform","configurationId":"` + configurationID.String() +
				`","configurationVersion":1,"healthy":false,"checkedAt":"2026-09-01T00:00:00Z",` +
				`"checks":[{"kind":"dns","kind":"connect","outcome":"failed","errorClass":"security"}]}`,
		},
		{
			name: "unknown sensitive field",
			body: `{"probeId":"` + probeID.String() + `","fenceToken":"` + fenceToken.String() +
				`","configurationScope":"platform","configurationId":"` + configurationID.String() +
				`","configurationVersion":1,"healthy":true,"checkedAt":"2026-09-01T00:00:00Z",` +
				`"checks":[{"kind":"connect","outcome":"passed"}],"banner":"must-not-cross"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			client, err := NewHTTPPreviewer(server.URL, []byte(strings.Repeat("s", 40)), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, err = client.ProbeSMTP(context.Background(), SMTPProbeRequest{
				ProbeID: probeID, FenceToken: fenceToken,
				ConfigurationScope: SMTPConfigurationPlatform,
				ConfigurationID:    configurationID, ConfigurationVersion: 1,
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("ProbeSMTP() error = %v", err)
			}
		})
	}
}

func TestHTTPPreviewerFailsClosed(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        error
	}{
		{name: "rate limited", status: http.StatusTooManyRequests, contentType: "application/problem+json", body: `{}`, want: ErrRateLimited},
		{name: "unexpected field", status: http.StatusOK, contentType: "application/json", body: `{"subject":"ok","html":"","plainText":"","secret":"leak"}`, want: ErrUnavailable},
		{name: "missing required field", status: http.StatusOK, contentType: "application/json", body: `{"subject":"ok","html":""}`, want: ErrUnavailable},
		{name: "duplicate field", status: http.StatusOK, contentType: "application/json", body: `{"subject":"first","subject":"second","html":"","plainText":""}`, want: ErrUnavailable},
		{name: "trailing value", status: http.StatusOK, contentType: "application/json", body: `{"subject":"ok","html":"","plainText":""}{}`, want: ErrUnavailable},
		{name: "wrong content type", status: http.StatusOK, contentType: "text/plain", body: `{"subject":"ok","html":"","plainText":""}`, want: ErrUnavailable},
		{name: "oversized", status: http.StatusOK, contentType: "application/json", body: strings.Repeat("x", maximumNotificationPreviewBody+1), want: ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Content-Type", test.contentType)
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer server.Close()
			previewer, err := NewHTTPPreviewer(server.URL, []byte(strings.Repeat("x", 40)), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer previewer.Close()
			_, err = previewer.Preview(context.Background(), mustV7(t), AudienceOperator, serviceTemplateFields(), map[string]any{})
			if !errors.Is(err, test.want) {
				t.Fatalf("Preview() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHTTPPreviewerRejectsUseAfterClose(t *testing.T) {
	previewer, err := NewHTTPPreviewer("https://notifier.internal", []byte(strings.Repeat("c", 40)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	previewer.Close()
	previewer.Close()
	_, err = previewer.Preview(context.Background(), mustV7(t), AudienceOperator, serviceTemplateFields(), map[string]any{})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Preview() error = %v", err)
	}
	_, err = previewer.ProbeSMTP(context.Background(), SMTPProbeRequest{
		ProbeID: mustV7(t), FenceToken: mustV7(t),
		ConfigurationScope: SMTPConfigurationPlatform,
		ConfigurationID:    mustV7(t), ConfigurationVersion: 1,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ProbeSMTP() error = %v", err)
	}
}
