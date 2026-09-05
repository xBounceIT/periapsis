package platformsamladapter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/origin"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	DirectSAMLDevelopmentTransactionCookie = "periapsis_platform_saml_transaction"
	DirectSAMLProductionTransactionCookie  = "__Host-periapsis_platform_saml_transaction"

	RedirectStatusSeeOther   = 303
	CacheControlNoStore      = "no-store"
	ReferrerPolicyNoReferrer = "no-referrer"
)

var (
	ErrTransportRejected    = errors.New("direct platform SAML browser transport rejected")
	ErrTransportUnavailable = errors.New("direct platform SAML browser transport unavailable")
)

type SameSiteMode string

const (
	SameSiteNone   SameSiteMode = "None"
	SameSiteStrict SameSiteMode = "Strict"
)

// CookieDirective is an HTTP-neutral cookie command. Domain is deliberately
// absent, which makes every emitted cookie host-only. Value ownership belongs
// to the directive and Destroy must be called after synchronous delivery.
type CookieDirective struct {
	Name     string
	Value    []byte `json:"-"`
	Path     string
	Expires  time.Time
	MaxAge   int
	Secure   bool
	HTTPOnly bool
	HostOnly bool
	SameSite SameSiteMode
}

func (cookie *CookieDirective) Destroy() {
	if cookie == nil {
		return
	}
	clear(cookie.Value)
	*cookie = CookieDirective{}
}

func (cookie CookieDirective) String() string {
	return fmt.Sprintf(
		"platformsamladapter.CookieDirective{name:%q,value:%t,path:%q,expires:%t,maxAge:%d,secure:%t,httpOnly:%t,hostOnly:%t,sameSite:%q,material:[REDACTED]}",
		cookie.Name, len(cookie.Value) != 0, cookie.Path, !cookie.Expires.IsZero(), cookie.MaxAge,
		cookie.Secure, cookie.HTTPOnly, cookie.HostOnly, cookie.SameSite,
	)
}

func (cookie CookieDirective) GoString() string { return cookie.String() }

type BrowserTransportPolicy struct {
	TransactionCookieName string
	ContinuationPath      string
}

type BrowserTransport struct {
	policy BrowserTransportPolicy
	now    func() time.Time
}

func NewBrowserTransport(policy BrowserTransportPolicy, now func() time.Time) (*BrowserTransport, error) {
	if !validTransactionCookieName(policy.TransactionCookieName) ||
		!validReturnPath(policy.ContinuationPath) || now == nil {
		return nil, ErrInvalidOptions
	}
	return &BrowserTransport{policy: policy, now: now}, nil
}

func (transport *BrowserTransport) String() string {
	return fmt.Sprintf(
		"platformsamladapter.BrowserTransport{configured:%t,cookie:%t,continuationPath:%t,material:[REDACTED]}",
		transport != nil && transport.now != nil, transport != nil && transport.policy.TransactionCookieName != "",
		transport != nil && transport.policy.ContinuationPath != "",
	)
}

func (transport *BrowserTransport) GoString() string { return transport.String() }

type RedirectResponse struct {
	StatusCode     int
	Location       string
	CacheControl   string
	ReferrerPolicy string
	Cookies        []CookieDirective
}

func (response *RedirectResponse) Destroy() {
	if response == nil {
		return
	}
	for index := range response.Cookies {
		response.Cookies[index].Destroy()
	}
	*response = RedirectResponse{}
}

func (response RedirectResponse) String() string {
	return fmt.Sprintf(
		"platformsamladapter.RedirectResponse{status:%d,location:%t,cacheControl:%q,referrerPolicy:%q,cookies:%d,material:[REDACTED]}",
		response.StatusCode, response.Location != "", response.CacheControl, response.ReferrerPolicy,
		len(response.Cookies),
	)
}

func (response RedirectResponse) GoString() string { return response.String() }

func (transport *BrowserTransport) StartRedirect(
	start *platformsamlauth.AuthorizationStart,
) (RedirectResponse, error) {
	if start == nil {
		return RedirectResponse{}, ErrTransportRejected
	}
	defer start.Destroy()
	handle, claimed := start.ConsumeBrowserHandle()
	defer clear(handle)
	if transport == nil || transport.now == nil || !claimed || !validSAMLRedirect(start.RedirectURL()) {
		return RedirectResponse{}, ErrTransportRejected
	}
	now, ok := canonicalNow(transport.now)
	if !ok || !validBrowserHandle(handle) || !validInstant(start.ExpiresAt()) ||
		!start.ExpiresAt().After(now) || start.ExpiresAt().After(now.Add(15*time.Minute)) {
		return RedirectResponse{}, ErrTransportRejected
	}
	maxAge := int(math.Ceil(start.ExpiresAt().Sub(now).Seconds()))
	if maxAge < 1 || maxAge > int((15*time.Minute)/time.Second) {
		return RedirectResponse{}, ErrTransportRejected
	}
	return RedirectResponse{
		StatusCode: RedirectStatusSeeOther, Location: start.RedirectURL(),
		CacheControl: CacheControlNoStore, ReferrerPolicy: ReferrerPolicyNoReferrer,
		Cookies: []CookieDirective{{
			Name: transport.policy.TransactionCookieName, Value: append([]byte(nil), handle...),
			Path: "/", Expires: start.ExpiresAt(), MaxAge: maxAge,
			Secure: true, HTTPOnly: true, HostOnly: true, SameSite: SameSiteNone,
		}},
	}, nil
}

type RequestCookie struct {
	Name  string
	Value string `json:"-"`
}

func (cookie RequestCookie) String() string {
	return fmt.Sprintf("platformsamladapter.RequestCookie{name:%q,value:%t,material:[REDACTED]}", cookie.Name, cookie.Value != "")
}

func (cookie RequestCookie) GoString() string { return cookie.String() }

// TransactionCapability is a process-local one-use ownership wrapper around
// the host-only callback cookie. Durable one-time semantics remain the exact
// RelayState+browser-digest transaction CAS in the kernel/persistence layer.
type TransactionCapability struct {
	guard    sync.Mutex
	handle   []byte
	consumed bool
}

func (capability *TransactionCapability) Consume() ([]byte, bool) {
	if capability == nil {
		return nil, false
	}
	capability.guard.Lock()
	defer capability.guard.Unlock()
	if capability.consumed || !validBrowserHandle(capability.handle) {
		capability.destroyLocked()
		return nil, false
	}
	handle := capability.handle
	capability.handle = nil
	capability.consumed = true
	return handle, true
}

func (capability *TransactionCapability) Destroy() {
	if capability == nil {
		return
	}
	capability.guard.Lock()
	defer capability.guard.Unlock()
	capability.destroyLocked()
}

func (capability *TransactionCapability) destroyLocked() {
	clear(capability.handle)
	capability.handle = nil
	capability.consumed = true
}

func (capability *TransactionCapability) String() string {
	return "platformsamladapter.TransactionCapability{authority:direct_platform_saml,material:[REDACTED]}"
}

func (capability *TransactionCapability) GoString() string { return capability.String() }

func (transport *BrowserTransport) ClaimTransactionCookie(
	cookies []RequestCookie,
) (*TransactionCapability, error) {
	if transport == nil || !validTransactionCookieName(transport.policy.TransactionCookieName) {
		return nil, ErrTransportRejected
	}
	var value string
	count := 0
	for _, cookie := range cookies {
		if cookie.Name == transport.policy.TransactionCookieName {
			count++
			value = cookie.Value
		}
	}
	handle := []byte(value)
	if count != 1 || !validBrowserHandle(handle) {
		clear(handle)
		return nil, ErrTransportRejected
	}
	return &TransactionCapability{handle: handle}, nil
}

func (transport *BrowserTransport) ClearTransactionCookie() (CookieDirective, error) {
	if transport == nil || !validTransactionCookieName(transport.policy.TransactionCookieName) {
		return CookieDirective{}, ErrTransportRejected
	}
	return CookieDirective{
		Name: transport.policy.TransactionCookieName, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
		Secure: true, HTTPOnly: true, HostOnly: true, SameSite: SameSiteNone,
	}, nil
}

type CredentialCookieRequirements struct {
	Path     string
	Secure   bool
	HTTPOnly bool
	HostOnly bool
	SameSite SameSiteMode
}

// BrowserDelivery is valid only for the synchronous duration of
// BrowserDeliverySink.DeliverDirectSAML. A sink must not retain it. The future
// HTTP adapter is responsible for its existing session/continuation cookie
// encoding and for re-resolving a session before setting the bearer cookie.
type BrowserDelivery struct {
	StatusCode       int
	Location         string
	CacheControl     string
	ReferrerPolicy   string
	ClearTransaction CookieDirective
	CookieSecurity   CredentialCookieRequirements
	Disposition      platformsamlauth.Disposition
	UserID           identity.EntityID
	SessionID        identity.EntityID
	ContinuationID   identity.EntityID
	ExpiresAt        time.Time
	SessionToken     []byte `json:"-"`
	CSRFToken        []byte `json:"-"`
	Receipt          []byte `json:"-"`
}

type browserDeliveryProof struct {
	statusCode       int
	location         string
	cacheControl     string
	referrerPolicy   string
	clearName        string
	clearPath        string
	clearExpires     time.Time
	clearMaxAge      int
	clearSecure      bool
	clearHTTPOnly    bool
	clearHostOnly    bool
	clearSameSite    SameSiteMode
	clearValueBytes  int
	clearValueDigest [sha256.Size]byte
	cookieSecurity   CredentialCookieRequirements
	disposition      platformsamlauth.Disposition
	userID           identity.EntityID
	sessionID        identity.EntityID
	continuationID   identity.EntityID
	expiresAt        time.Time
	sessionBytes     int
	csrfBytes        int
	receiptBytes     int
	sessionDigest    [sha256.Size]byte
	csrfDigest       [sha256.Size]byte
	receiptDigest    [sha256.Size]byte
}

func (delivery *BrowserDelivery) Destroy() {
	if delivery == nil {
		return
	}
	delivery.ClearTransaction.Destroy()
	clear(delivery.SessionToken)
	clear(delivery.CSRFToken)
	clear(delivery.Receipt)
	*delivery = BrowserDelivery{}
}

func (delivery BrowserDelivery) String() string {
	return fmt.Sprintf(
		"platformsamladapter.BrowserDelivery{status:%d,location:%t,disposition:%q,user:%t,session:%t,continuation:%t,expires:%t,cookieSecurity:%t,material:[REDACTED]}",
		delivery.StatusCode, delivery.Location != "", delivery.Disposition,
		validUUIDv7(delivery.UserID), validUUIDv7(delivery.SessionID), validUUIDv7(delivery.ContinuationID),
		!delivery.ExpiresAt.IsZero(), validCredentialCookieRequirements(delivery.CookieSecurity),
	)
}

func (delivery BrowserDelivery) GoString() string { return delivery.String() }

type BrowserDeliverySink interface {
	DeliverDirectSAML(context.Context, *BrowserDelivery) error
}

type browserCredential interface {
	Consume() (platformsamlauth.BrowserCredentialMaterial, bool)
	Destroy()
}

type browserDeliveryFinalizer interface {
	ConfirmBrowserDelivery() error
	CompensateBrowserDelivery(context.Context) error
}

func (transport *BrowserTransport) DeliverApplicationOutcome(
	ctx context.Context,
	outcome *platformsamlauth.Outcome,
	sink BrowserDeliverySink,
) error {
	if outcome == nil {
		return ErrTransportRejected
	}
	return transport.deliver(ctx, outcome, outcome.Credential, sink, outcome)
}

func (transport *BrowserTransport) deliver(
	ctx context.Context,
	outcome *platformsamlauth.Outcome,
	credential browserCredential,
	sink BrowserDeliverySink,
	finalizer browserDeliveryFinalizer,
) error {
	var material platformsamlauth.BrowserCredentialMaterial
	var delivery BrowserDelivery
	destroyPlaintext := func() {
		delivery.Destroy()
		material.Destroy()
		if credential != nil {
			credential.Destroy()
		}
	}
	defer destroyPlaintext()
	fail := func() error {
		// Compensation may consume its entire bounded retry budget. Plaintext
		// ownership ends before that I/O begins, not merely on function return.
		destroyPlaintext()
		if outcome == nil || finalizer == nil {
			return ErrTransportRejected
		}
		err := finalizer.CompensateBrowserDelivery(ctx)
		if errors.Is(err, platformsamlauth.ErrBrowserDeliveryUnavailable) {
			return ErrTransportUnavailable
		}
		return ErrTransportRejected
	}
	if transport == nil || transport.now == nil || !activeContext(ctx) || sink == nil || credential == nil ||
		outcome == nil || !validUUIDv7(outcome.UserID) || !validReturnPath(outcome.ReturnPath) {
		return fail()
	}
	var ok bool
	material, ok = credential.Consume()
	if !ok {
		return fail()
	}
	now, timeOK := canonicalNow(transport.now)
	clearCookie, cookieErr := transport.ClearTransactionCookie()
	if !timeOK || cookieErr != nil || !validOutcomeMaterial(*outcome, material, now) {
		clearCookie.Destroy()
		return fail()
	}
	location := outcome.ReturnPath
	if outcome.Disposition == platformsamlauth.TOTPContinuation {
		location = transport.policy.ContinuationPath
	}
	delivery = BrowserDelivery{
		StatusCode: RedirectStatusSeeOther, Location: location,
		CacheControl: CacheControlNoStore, ReferrerPolicy: ReferrerPolicyNoReferrer,
		ClearTransaction: clearCookie,
		CookieSecurity: CredentialCookieRequirements{
			Path: "/", Secure: true, HTTPOnly: true, HostOnly: true, SameSite: SameSiteStrict,
		},
		Disposition: outcome.Disposition, UserID: outcome.UserID,
		SessionID: outcome.SessionID, ContinuationID: outcome.ContinuationID,
		ExpiresAt:    material.ExpiresAt,
		SessionToken: append([]byte(nil), material.SessionToken...),
		CSRFToken:    append([]byte(nil), material.CSRFToken...),
		Receipt:      append([]byte(nil), material.Receipt...),
	}
	deliveryProof := proveBrowserDelivery(delivery)
	defer deliveryProof.clear()
	if err := sink.DeliverDirectSAML(ctx, &delivery); err != nil || ctx.Err() != nil {
		return fail()
	}
	observedDeliveryProof := proveBrowserDelivery(delivery)
	deliveryUnchanged := observedDeliveryProof == deliveryProof
	observedDeliveryProof.clear()
	if !deliveryUnchanged {
		return fail()
	}
	if err := finalizer.ConfirmBrowserDelivery(); err != nil {
		return fail()
	}
	return nil
}

func proveBrowserDelivery(delivery BrowserDelivery) browserDeliveryProof {
	return browserDeliveryProof{
		statusCode: delivery.StatusCode, location: delivery.Location,
		cacheControl: delivery.CacheControl, referrerPolicy: delivery.ReferrerPolicy,
		clearName: delivery.ClearTransaction.Name, clearPath: delivery.ClearTransaction.Path,
		clearExpires: delivery.ClearTransaction.Expires, clearMaxAge: delivery.ClearTransaction.MaxAge,
		clearSecure: delivery.ClearTransaction.Secure, clearHTTPOnly: delivery.ClearTransaction.HTTPOnly,
		clearHostOnly: delivery.ClearTransaction.HostOnly, clearSameSite: delivery.ClearTransaction.SameSite,
		clearValueBytes:  len(delivery.ClearTransaction.Value),
		clearValueDigest: sha256.Sum256(delivery.ClearTransaction.Value),
		cookieSecurity:   delivery.CookieSecurity, disposition: delivery.Disposition, userID: delivery.UserID,
		sessionID: delivery.SessionID, continuationID: delivery.ContinuationID, expiresAt: delivery.ExpiresAt,
		sessionBytes: len(delivery.SessionToken), csrfBytes: len(delivery.CSRFToken), receiptBytes: len(delivery.Receipt),
		sessionDigest: sha256.Sum256(delivery.SessionToken), csrfDigest: sha256.Sum256(delivery.CSRFToken),
		receiptDigest: sha256.Sum256(delivery.Receipt),
	}
}

func (proof *browserDeliveryProof) clear() {
	if proof == nil {
		return
	}
	*proof = browserDeliveryProof{}
}

func validOutcomeMaterial(
	outcome platformsamlauth.Outcome,
	material platformsamlauth.BrowserCredentialMaterial,
	now time.Time,
) bool {
	switch outcome.Disposition {
	case platformsamlauth.ImmediateSession:
		return material.Kind == platformsamlauth.BrowserSessionCredential &&
			validUUIDv7(outcome.SessionID) && outcome.SessionID == material.SessionID &&
			outcome.ContinuationID == (identity.EntityID{}) && material.ContinuationID == (identity.EntityID{}) &&
			material.ExpiresAt.IsZero() && validBrowserHandle(material.SessionToken) &&
			validBrowserHandle(material.CSRFToken) && len(material.Receipt) == 0
	case platformsamlauth.TOTPContinuation:
		return material.Kind == platformsamlauth.BrowserContinuationCredential &&
			outcome.SessionID == (identity.EntityID{}) && material.SessionID == (identity.EntityID{}) &&
			validUUIDv7(outcome.ContinuationID) && outcome.ContinuationID == material.ContinuationID &&
			validInstant(material.ExpiresAt) && material.ExpiresAt.After(now) &&
			!material.ExpiresAt.After(now.Add(15*time.Minute)) && len(material.SessionToken) == 0 &&
			len(material.CSRFToken) == 0 && validBrowserHandle(material.Receipt)
	default:
		return false
	}
}

func validCredentialCookieRequirements(value CredentialCookieRequirements) bool {
	return value.Path == "/" && value.Secure && value.HTTPOnly && value.HostOnly && value.SameSite == SameSiteStrict
}

func validTransactionCookieName(value string) bool {
	return value == DirectSAMLDevelopmentTransactionCookie || value == DirectSAMLProductionTransactionCookie
}

func validSAMLRedirect(raw string) bool {
	if raw == "" || len(raw) > maximumRedirectBytes || strings.ContainsAny(raw, "\\\r\n") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" || parsed.Hostname() == "" ||
		strings.Contains(parsed.Host, "%") || strings.HasSuffix(parsed.Host, ":") || parsed.String() != raw {
		return false
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil {
		return false
	}
	port := parsed.Port()
	if port != "" {
		numericPort, portErr := strconv.Atoi(port)
		if portErr != nil || numericPort < 1 || numericPort > 65535 || numericPort == 443 {
			return false
		}
		port = strconv.Itoa(numericPort)
	}
	canonicalHost := hostname
	if strings.Contains(hostname, ":") {
		canonicalHost = "[" + hostname + "]"
	}
	if port != "" {
		canonicalHost = net.JoinHostPort(hostname, port)
	}
	if parsed.Host != canonicalHost {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 4 {
		return false
	}
	for _, name := range []string{"SAMLRequest", "RelayState", "SigAlg", "Signature"} {
		values, exists := query[name]
		if !exists || len(values) != 1 || values[0] == "" {
			return false
		}
	}
	relay := []byte(query.Get("RelayState"))
	if len(relay) > maximumRelayStateBytes || !validBrowserHandle(relay) {
		return false
	}
	algorithm := federatedsaml.RedirectSignatureAlgorithm(query.Get("SigAlg"))
	switch algorithm {
	case federatedsaml.RedirectRSASHA256, federatedsaml.RedirectRSASHA384, federatedsaml.RedirectRSASHA512,
		federatedsaml.RedirectECDSASHA256, federatedsaml.RedirectECDSASHA384, federatedsaml.RedirectECDSASHA512:
		return true
	default:
		return false
	}
}
