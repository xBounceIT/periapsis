package federatedhttp

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
)

const maximumOperationBodyBytes = 512 * 1024

// OperationKind is the closed set of credential-bearing OIDC calls allowed
// against a previously compiled target. These calls never redirect.
type OperationKind string

const (
	OperationOIDCToken      OperationKind = "oidc_token"
	OperationOIDCUserInfo   OperationKind = "oidc_userinfo"
	OperationOIDCRevocation OperationKind = "oidc_revocation"
)

// OperationRequest transfers ownership of Authorization and Body to Execute.
// Both slices are cleared before Execute returns.
type OperationRequest struct {
	Kind             OperationKind
	Target           Target
	Authorization    []byte `json:"-"`
	Body             []byte `json:"-"`
	MaxResponseBytes int64
}

func (request OperationRequest) String() string {
	return "federatedhttp.OperationRequest{material:[REDACTED]}"
}

func (request OperationRequest) GoString() string { return request.String() }

// OperationResult contains only a bounded response body on success. Body is
// empty for rejected status, media type, size, cancellation, and network
// outcomes. RequestNotDispatched is true only when the concrete transport can
// prove that no request bytes reached an established upstream connection.
type OperationResult struct {
	Category             Category
	StatusCode           int
	MediaType            string
	Body                 []byte `json:"-"`
	RequestNotDispatched bool
}

type operationDispatchEvidenceKey struct{}

type operationDispatchEvidence struct {
	connectionReturned atomic.Bool
}

func dispatchEvidenceFromContext(ctx context.Context) *operationDispatchEvidence {
	if ctx == nil {
		return nil
	}
	evidence, _ := ctx.Value(operationDispatchEvidenceKey{}).(*operationDispatchEvidence)
	return evidence
}

func (result OperationResult) String() string {
	return "federatedhttp.OperationResult{category:" + result.Category.String() + ",body:[REDACTED]}"
}

func (result OperationResult) GoString() string { return result.String() }

// Execute performs one credential-bearing request with the same resolver,
// literal-IP dialer, TLS roots, egress policy, concurrency budget, and total
// deadline as document retrieval. It bypasses http.Client redirect behavior by
// invoking the hardened transport exactly once.
func (client *Client) Execute(ctx context.Context, request OperationRequest) (OperationResult, error) {
	defer clear(request.Authorization)
	defer clear(request.Body)
	if client == nil || ctx == nil || !validOperationRequest(client, request) {
		return OperationResult{}, ErrInvalidTarget
	}
	validated, targetURL, err := client.validatedTarget(request.Target)
	if err != nil || validated.kind != DocumentOIDCDiscovery {
		return OperationResult{}, ErrInvalidTarget
	}
	if contextEnded(ctx) {
		return OperationResult{
			Category:             categoryFromContexts(ctx, ctx, CategoryOperationTimeout),
			RequestNotDispatched: true,
		}, nil
	}
	select {
	case client.slots <- struct{}{}:
		defer func() { <-client.slots }()
	default:
		return OperationResult{}, ErrBusy
	}

	operationCtx, cancel := context.WithTimeout(ctx, client.limits.OperationTimeout)
	defer cancel()
	dispatchEvidence := &operationDispatchEvidence{}
	operationCtx = context.WithValue(operationCtx, operationDispatchEvidenceKey{}, dispatchEvidence)
	method := http.MethodGet
	var body io.Reader
	if request.Kind != OperationOIDCUserInfo {
		method = http.MethodPost
		body = bytes.NewReader(request.Body)
	}
	httpRequest, err := http.NewRequestWithContext(operationCtx, method, targetURL.String(), body)
	if err != nil {
		return OperationResult{Category: CategoryResponseFailed, RequestNotDispatched: true}, nil
	}
	httpRequest.Header.Set("Accept", operationAccept(request.Kind))
	httpRequest.Header.Set("Accept-Encoding", "identity")
	httpRequest.Header.Set("Cache-Control", "no-store")
	httpRequest.Header.Set("User-Agent", "Periapsis-Federated-Upstream/1")
	if len(request.Authorization) != 0 {
		httpRequest.Header.Set("Authorization", string(request.Authorization))
	}
	if method == http.MethodPost {
		httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	response, roundTripErr := client.transport.RoundTrip(httpRequest)
	httpRequest.Header.Del("Authorization")
	if roundTripErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		category, requestNotDispatched := operationRoundTripFailure(operationCtx, roundTripErr)
		return OperationResult{Category: category, RequestNotDispatched: requestNotDispatched}, nil
	}
	if response == nil || response.Body == nil {
		return OperationResult{Category: CategoryResponseFailed}, nil
	}
	defer response.Body.Close()
	result := OperationResult{StatusCode: response.StatusCode}
	if !acceptedOperationStatus(request.Kind, response.StatusCode) {
		result.Category = CategoryHTTPStatusRejected
		return result, nil
	}
	if request.Kind == OperationOIDCRevocation {
		result.Category = CategorySuccess
		return result, nil
	}
	if len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Encoding") != "" {
		result.Category = CategoryMediaTypeRejected
		return result, nil
	}
	mediaType, parameters, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || !strings.EqualFold(mediaType, "application/json") ||
		!validUTF8MediaParameters(parameters) {
		result.Category = CategoryMediaTypeRejected
		return result, nil
	}
	if response.ContentLength > request.MaxResponseBytes {
		result.Category = CategoryLimitExceeded
		return result, nil
	}
	limited := io.LimitReader(response.Body, request.MaxResponseBytes+1)
	responseBody, readErr := io.ReadAll(limited)
	if readErr != nil {
		result.Category = categoryFromContexts(operationCtx, operationCtx, CategoryResponseFailed)
		return result, nil
	}
	if int64(len(responseBody)) == 0 || int64(len(responseBody)) > request.MaxResponseBytes {
		clear(responseBody)
		result.Category = CategoryLimitExceeded
		return result, nil
	}
	result.Category = CategorySuccess
	result.MediaType = response.Header.Get("Content-Type")
	result.Body = responseBody
	return result, nil
}

func validOperationRequest(client *Client, request OperationRequest) bool {
	if !validOperationKind(request.Kind) || request.MaxResponseBytes < 1 ||
		request.MaxResponseBytes > client.limits.MaxDocumentBytes ||
		len(request.Authorization) > maximumAuthorizationBytes ||
		!validAuthorization(request.Authorization) || len(request.Body) > maximumOperationBodyBytes {
		return false
	}
	switch request.Kind {
	case OperationOIDCUserInfo:
		return len(request.Authorization) != 0 && len(request.Body) == 0
	case OperationOIDCToken, OperationOIDCRevocation:
		return len(request.Body) != 0
	default:
		return false
	}
}

func validOperationKind(kind OperationKind) bool {
	return kind == OperationOIDCToken || kind == OperationOIDCUserInfo || kind == OperationOIDCRevocation
}

func acceptedOperationStatus(kind OperationKind, status int) bool {
	if kind == OperationOIDCRevocation {
		return status == http.StatusOK || status == http.StatusNoContent
	}
	return status == http.StatusOK
}

func operationAccept(kind OperationKind) string {
	if kind == OperationOIDCRevocation {
		return "application/json, */*;q=0.1"
	}
	return "application/json"
}

func validUTF8MediaParameters(parameters map[string]string) bool {
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}
