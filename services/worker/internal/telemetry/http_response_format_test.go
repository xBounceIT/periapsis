package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTraceResponseWriterPreservesDeclaredFormatsAndStatus(t *testing.T) {
	for _, format := range []struct{ name, contentType, body string }{
		{"json", "application/json; charset=utf-8", "{\"value\":\"\\u003cscript\\u003etext\\u003c/script\\u003e\"}\n"},
		{"problem", "application/problem+json; charset=utf-8", "{\"status\":400,\"detail\":\"\\u003cscript\\u003etext\\u003c/script\\u003e\"}\n"},
		{"plaintext", "text/plain; charset=utf-8", "<script>text only</script>&\n"},
		{"metrics", "text/plain; version=0.0.4; charset=utf-8", "# HELP fixture <bounded> & literal\nfixture_total 1\n"},
		{"events", "text/event-stream", "event: fixture\ndata: {\"value\":\"<bounded>&\"}\n\n"},
	} {
		t.Run(format.name, func(t *testing.T) {
			for _, explicitStatus := range []bool{false, true} {
				runtime, exporter := inMemoryRuntime(t)
				handler := runtime.WrapHTTP(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Content-Type", format.contentType)
					writer.Header().Set("X-Content-Type-Options", "nosniff")
					if explicitStatus {
						writer.WriteHeader(http.StatusBadRequest)
					}
					if _, err := writer.Write([]byte(format.body)); err != nil {
						t.Error("write response fixture")
					}
				}))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/response-boundary", nil))
				expectedStatus := http.StatusOK
				if explicitStatus {
					expectedStatus = http.StatusBadRequest
				}
				if response.Code != expectedStatus || response.Header().Get("Content-Type") != format.contentType || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Body.String() != format.body {
					t.Fatal("trace wrapper rewrote the response format, status or bytes")
				}
				if len(exporter.GetSpans()) != 1 {
					t.Fatal("enabled trace response wrapper was not exercised")
				}
				if (format.name == "json" || format.name == "problem") && !json.Valid(response.Body.Bytes()) {
					t.Fatal("trace wrapper corrupted JSON escaping")
				}
			}
		})
	}
}
