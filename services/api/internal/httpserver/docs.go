package httpserver

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

//go:embed swagger-ui/*
var swaggerUI embed.FS

func registerDocumentation(mux *http.ServeMux, enabled bool) {
	if !enabled {
		return
	}

	assets, err := fs.Sub(swaggerUI, "swagger-ui")
	if err != nil {
		panic("embedded Swagger UI assets are unavailable")
	}

	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = contract.WriteDocumentation(w)
	})
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusPermanentRedirect)
	})
	mux.Handle("GET /docs/", http.StripPrefix("/docs/", http.FileServer(http.FS(assets))))
}
