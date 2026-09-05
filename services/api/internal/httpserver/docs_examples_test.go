package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocumentationServesGeneratedExamples(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerDocumentation(mux, true)

	specificationResponse := httptest.NewRecorder()
	mux.ServeHTTP(
		specificationResponse,
		httptest.NewRequest(http.MethodGet, "/openapi.json", nil),
	)
	if specificationResponse.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json status = %d, want %d", specificationResponse.Code, http.StatusOK)
	}
	if got := specificationResponse.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("GET /openapi.json Content-Type = %q", got)
	}

	var specification struct {
		Examples struct {
			Coverage    map[string]json.RawMessage `json:"coverage"`
			GeneratedBy string                     `json:"generatedBy"`
		} `json:"x-periapsis-generated-examples"`
		Tags []struct {
			Name string `json:"name"`
		} `json:"tags"`
	}
	if err := json.Unmarshal(specificationResponse.Body.Bytes(), &specification); err != nil {
		t.Fatalf("decode GET /openapi.json: %v", err)
	}
	if specification.Examples.GeneratedBy != "openapi-sampler@1.7.4+ajv@8.17.1+ajv-formats@3.0.1" {
		t.Fatalf("generated example provenance = %q", specification.Examples.GeneratedBy)
	}
	if len(specification.Examples.Coverage) == 0 || len(specification.Examples.Coverage) != len(specification.Tags) {
		t.Fatalf(
			"generated example tag coverage = %d, declared tags = %d",
			len(specification.Examples.Coverage),
			len(specification.Tags),
		)
	}

	initializerResponse := httptest.NewRecorder()
	mux.ServeHTTP(
		initializerResponse,
		httptest.NewRequest(http.MethodGet, "/docs/initializer.js", nil),
	)
	if initializerResponse.Code != http.StatusOK {
		t.Fatalf("GET /docs/initializer.js status = %d, want %d", initializerResponse.Code, http.StatusOK)
	}
	if !strings.Contains(initializerResponse.Body.String(), `url: "/openapi.json"`) {
		t.Fatal("Swagger UI does not load the enriched /openapi.json bundle")
	}
}
