package federatedhttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (client *Client) readDocument(
	ctx context.Context,
	kind DocumentKind,
	response *http.Response,
	redirects int,
	credentialBearing bool,
) Result {
	result := Result{Category: CategoryResponseFailed, Kind: kind, Redirects: redirects}
	if response == nil || response.Body == nil {
		return result
	}
	defer response.Body.Close()
	if !validMediaType(kind, response.Header.Values("Content-Type")) {
		result.Category = CategoryMediaTypeRejected
		return result
	}
	encoding, ok := responseEncoding(response.Header.Values("Content-Encoding"))
	if !ok {
		result.Category = CategoryEncodingRejected
		return result
	}
	if response.ContentLength > client.limits.MaxWireBytes {
		result.Category = CategoryLimitExceeded
		return result
	}
	wire, tooLarge, err := readBounded(response.Body, client.limits.MaxWireBytes)
	if err != nil {
		result.Category = responseReadCategory(ctx, err)
		return result
	}
	if contextEnded(ctx) {
		clear(wire)
		result.Category = categoryFromContexts(ctx, ctx, CategoryOperationTimeout)
		return result
	}
	if tooLarge {
		result.Category = CategoryLimitExceeded
		return result
	}

	document := wire
	if encoding == "gzip" {
		decoded, category := decompressGZIP(wire, client.limits.MaxDocumentBytes)
		clear(wire)
		if category != CategorySuccess {
			result.Category = category
			return result
		}
		document = decoded
	} else if int64(len(document)) > client.limits.MaxDocumentBytes {
		clear(document)
		result.Category = CategoryLimitExceeded
		return result
	}
	if len(document) == 0 {
		result.Category = CategoryResponseFailed
		return result
	}

	retrievedAt := time.Now().UTC().Truncate(time.Microsecond)
	cache := cacheMetadata(retrievedAt, response.Header, client.limits)
	if credentialBearing {
		cache.Cacheable = false
		cache.MustRevalidate = true
		cache.FreshUntil = retrievedAt
	}
	result.Category = CategorySuccess
	result.Body = document
	result.Digest = sha256.Sum256(document)
	result.Cache = cache
	return result
}

func validMediaType(kind DocumentKind, values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil {
		return false
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	switch kind {
	case DocumentOIDCDiscovery:
		return strings.EqualFold(mediaType, "application/json")
	case DocumentOIDCJWKS:
		return strings.EqualFold(mediaType, "application/jwk-set+json") ||
			strings.EqualFold(mediaType, "application/json")
	case DocumentSAMLMetadata:
		return strings.EqualFold(mediaType, "application/samlmetadata+xml") ||
			strings.EqualFold(mediaType, "application/xml") ||
			strings.EqualFold(mediaType, "text/xml")
	default:
		return false
	}
}

func responseEncoding(values []string) (string, bool) {
	if len(values) == 0 {
		return "identity", true
	}
	if len(values) != 1 || strings.ContainsRune(values[0], ',') {
		return "", false
	}
	value := strings.ToLower(strings.TrimSpace(values[0]))
	switch value {
	case "identity":
		return "identity", true
	case "gzip":
		return "gzip", true
	default:
		return "", false
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, bool, error) {
	if reader == nil || maximum < 1 {
		return nil, false, errors.New("bounded response read failed")
	}
	value, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		clear(value)
		return nil, false, err
	}
	if int64(len(value)) > maximum {
		clear(value)
		return nil, true, nil
	}
	return value, false, nil
}

func decompressGZIP(compressed []byte, maximum int64) ([]byte, Category) {
	input := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(input)
	if err != nil {
		return nil, CategoryEncodingRejected
	}
	reader.Multistream(false)
	decoded, tooLarge, readErr := readBounded(reader, maximum)
	closeErr := reader.Close()
	if tooLarge {
		return nil, CategoryLimitExceeded
	}
	if readErr != nil || closeErr != nil || input.Len() != 0 {
		clear(decoded)
		return nil, CategoryEncodingRejected
	}
	return decoded, CategorySuccess
}

func responseReadCategory(ctx context.Context, err error) Category {
	if contextEnded(ctx) {
		return categoryFromContexts(ctx, ctx, CategoryOperationTimeout)
	}
	var networkError interface{ Timeout() bool }
	if errors.As(err, &networkError) && networkError.Timeout() {
		return CategoryOperationTimeout
	}
	return CategoryResponseFailed
}

func cacheMetadata(retrievedAt time.Time, headers http.Header, limits Limits) CacheMetadata {
	metadata := CacheMetadata{
		RetrievedAt: retrievedAt,
		FreshUntil:  retrievedAt.Add(limits.DefaultCacheAge),
		Cacheable:   true,
	}
	directives, valid := parseCacheControl(headers.Values("Cache-Control"), limits.MaxCacheAge)
	if !valid {
		metadata.FreshUntil = retrievedAt
		metadata.MustRevalidate = true
		return metadata
	}
	if directives.noStore {
		metadata.Cacheable = false
		metadata.MustRevalidate = true
		metadata.FreshUntil = retrievedAt
		return metadata
	}
	if directives.maxAge != nil {
		metadata.FreshUntil = retrievedAt.Add(*directives.maxAge)
	} else if expiresValues := headers.Values("Expires"); len(expiresValues) != 0 {
		if len(expiresValues) != 1 {
			metadata.FreshUntil = retrievedAt
			metadata.MustRevalidate = true
			return metadata
		}
		expiresAt, err := http.ParseTime(expiresValues[0])
		if err != nil {
			metadata.FreshUntil = retrievedAt
			metadata.MustRevalidate = true
			return metadata
		}
		metadata.FreshUntil = expiresAt.UTC()
	}

	if ageValues := headers.Values("Age"); len(ageValues) != 0 {
		if len(ageValues) != 1 {
			metadata.FreshUntil = retrievedAt
			metadata.MustRevalidate = true
			return metadata
		}
		ageSeconds, err := parseCanonicalSeconds(ageValues[0], limits.MaxCacheAge)
		if err != nil {
			metadata.FreshUntil = retrievedAt
			metadata.MustRevalidate = true
			return metadata
		}
		metadata.FreshUntil = metadata.FreshUntil.Add(-ageSeconds)
	}
	maximumFreshUntil := retrievedAt.Add(limits.MaxCacheAge)
	if metadata.FreshUntil.After(maximumFreshUntil) {
		metadata.FreshUntil = maximumFreshUntil
	}
	if metadata.FreshUntil.Before(retrievedAt) {
		metadata.FreshUntil = retrievedAt
	}
	metadata.MustRevalidate = directives.mustRevalidate || directives.noCache
	if directives.noCache || pragmaNoCache(headers.Values("Pragma")) {
		metadata.FreshUntil = retrievedAt
		metadata.MustRevalidate = true
	}
	return metadata
}

type cacheControlDirectives struct {
	maxAge         *time.Duration
	noStore        bool
	noCache        bool
	mustRevalidate bool
}

func parseCacheControl(values []string, maximum time.Duration) (cacheControlDirectives, bool) {
	var result cacheControlDirectives
	for _, headerValue := range values {
		for _, rawDirective := range strings.Split(headerValue, ",") {
			directive := strings.TrimSpace(rawDirective)
			if directive == "" {
				return cacheControlDirectives{}, false
			}
			name, value, hasValue := strings.Cut(directive, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			switch name {
			case "max-age":
				if !hasValue {
					return cacheControlDirectives{}, false
				}
				duration, err := parseCanonicalSeconds(strings.TrimSpace(value), maximum)
				if err != nil || result.maxAge != nil && *result.maxAge != duration {
					return cacheControlDirectives{}, false
				}
				result.maxAge = &duration
			case "no-store":
				if hasValue {
					return cacheControlDirectives{}, false
				}
				result.noStore = true
			case "no-cache":
				if hasValue {
					return cacheControlDirectives{}, false
				}
				result.noCache = true
			case "must-revalidate":
				if hasValue {
					return cacheControlDirectives{}, false
				}
				result.mustRevalidate = true
			default:
				if name == "" {
					return cacheControlDirectives{}, false
				}
			}
		}
	}
	return result, true
}

func parseCanonicalSeconds(value string, maximum time.Duration) (time.Duration, error) {
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(seconds, 10) != value {
		return 0, errors.New("invalid cache duration")
	}
	maximumSeconds := uint64(maximum / time.Second)
	if seconds > maximumSeconds {
		seconds = maximumSeconds
	}
	return time.Duration(seconds) * time.Second, nil
}

func pragmaNoCache(values []string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), "no-cache") {
			return true
		}
	}
	return false
}
