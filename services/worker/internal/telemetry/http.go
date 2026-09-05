package telemetry

import (
	"net/http"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var routePattern = regexp.MustCompile(`^(?:[A-Z]+ )?/[A-Za-z0-9_./{}*:-]{0,240}$`)

// WrapHTTP creates server spans without recording raw paths, queries, headers,
// request bodies, peer addresses, user agents, or tenant identifiers.
func (r *Runtime) WrapHTTP(next http.Handler) http.Handler {
	if next == nil {
		panic("telemetry: HTTP handler is required")
	}
	if r == nil || !r.enabled {
		return next
	}
	tracer := r.Tracer()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method := canonicalHTTPMethod(request.Method)
		parent := extractHTTPTraceContext(request.Context(), request.Header)
		ctx, span := tracer.Start(
			parent, "HTTP "+method,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(attribute.String("http.request.method", method)),
		)
		recorder := &traceResponseWriter{ResponseWriter: writer, status: http.StatusOK}
		tracedRequest := request.WithContext(ctx)
		defer func() {
			panicked := recover()
			status := recorder.status
			if panicked != nil {
				status = http.StatusInternalServerError
			}
			if pattern := canonicalRoutePattern(tracedRequest.Pattern); pattern != "" {
				span.SetName(pattern)
				span.SetAttributes(attribute.String("http.route", pattern))
			}
			span.SetAttributes(attribute.Int("http.response.status_code", status))
			if panicked != nil {
				span.SetAttributes(attribute.String("error.type", "panic"))
				span.SetStatus(codes.Error, "HTTP handler panic")
			} else if recorder.status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, "HTTP server error")
			}
			span.End()
			if panicked != nil {
				panic(panicked)
			}
		}()
		next.ServeHTTP(recorder, tracedRequest)
	})
}

type traceResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *traceResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *traceResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *traceResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func canonicalHTTPMethod(input string) string {
	if len(input) < 1 || len(input) > 16 {
		return "OTHER"
	}
	for _, character := range input {
		if character < 'A' || character > 'Z' {
			return "OTHER"
		}
	}
	return input
}

func canonicalRoutePattern(input string) string {
	if input == "" || len(input) > 256 || strings.ContainsAny(input, "?\r\n") || !routePattern.MatchString(input) {
		return ""
	}
	return input
}
