package securityaudit

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	defaultPageSize      = 50
	maximumPageSize      = 100
	maximumSearchRunes   = 256
	maximumDocumentBytes = 64 * 1024
	maximumMetadataBytes = 16 * 1024
	maximumJSONDepth     = 32
	maximumJSONNodes     = 8_192
	zeroAuditHash        = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	stableKeyPattern            = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)*$`)
	authenticationMethodPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:+-]{0,63}$`)
	hashPattern                 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	prohibitedKeys              = map[string]struct{}{
		"accesstoken": {}, "accesstokendigest": {}, "apikey": {}, "apikeydigest": {},
		"assertion": {}, "authorization": {}, "bindpassword": {}, "clientassertion": {},
		"clientsecret": {}, "cookie": {}, "credential": {}, "credentials": {},
		"csrfsecret": {}, "csrfsecretdigest": {}, "csrftoken": {}, "encryptionkey": {},
		"idtoken": {}, "idtokendigest": {}, "keymaterial": {}, "passphrase": {},
		"password": {}, "passwordphc": {}, "privatekey": {}, "privatekeyciphertext": {},
		"recoverycode": {}, "recoverycodes": {}, "refreshtoken": {}, "refreshtokendigest": {},
		"samlassertion": {}, "secret": {}, "secretciphertext": {}, "sessiontoken": {},
		"token": {}, "tokendigest": {}, "totpsecret": {},
	}
	safeSensitiveBooleanKeys = map[string]struct{}{
		"authorizationinitialized": {}, "bindsecretconfigured": {},
		"passwordconfigured": {}, "privatekeyconfigured": {},
		"secretmaterialarchived": {}, "secretmaterialincluded": {},
	}
	safeSensitiveIdentifierKeys = map[string]struct{}{
		"apikeyid": {}, "bindsecretid": {}, "credentialid": {},
		"fencetoken": {}, "predecessorcredentialid": {}, "replacementcredentialid": {},
		"secretid": {},
	}
	safeSensitiveIntegerKeys = map[string]struct{}{
		"authorizationrevision": {}, "bindsecretkeyversion": {}, "bindsecretversion": {},
		"credentialkeyversion": {}, "credentialversion": {}, "secretversion": {},
	}
	safeSensitiveKindKeys = map[string]struct{}{
		"bindsecretalgorithm": {}, "credentialkind": {}, "secretkind": {}, "tokenkind": {},
	}
	safeSensitiveKeyCatalogs = []map[string]struct{}{
		safeSensitiveBooleanKeys,
		safeSensitiveIdentifierKeys,
		safeSensitiveIntegerKeys,
		safeSensitiveKindKeys,
	}
	sensitiveKeyFragments = []string{
		"accesstoken", "apikey", "assertion", "bindpassword", "clientassertion",
		"clientsecret", "cookie", "credential", "csrfsecret", "csrftoken",
		"encryptionkey", "idtoken", "keymaterial", "passphrase", "password",
		"privatekey", "recoverycode", "refreshtoken", "samlassertion", "secret",
		"sessiontoken", "token", "totpsecret",
	}
)

type Service struct {
	repository Repository
	resolver   AuthorityResolver
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
	now        func() time.Time
}

func NewService(repository Repository, resolver AuthorityResolver) (*Service, error) {
	if repository == nil || resolver == nil {
		return nil, errors.New("audit repository and authority resolver are required")
	}
	return &Service{
		repository: repository,
		resolver:   resolver,
		evaluator:  authorization.Evaluator{},
		newID:      uuid.NewV7,
		now:        time.Now,
	}, nil
}

func (service *Service) ListTenant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	query Query,
	audit authorization.AuditContext,
) (Page, error) {
	query, err := normalizeQuery(query)
	if err != nil || !validTenantAudit(audit) {
		return Page{}, ErrInvalidInput
	}
	if !validTenantActor(actor, tenantID) {
		return Page{}, ErrForbidden
	}
	if err := service.requireTenantAuditRead(ctx, actor, tenantID); err != nil {
		return Page{}, err
	}
	accessAuditID, err := service.newAuditID()
	if err != nil {
		return Page{}, err
	}
	rows, err := service.repository.ListTenantEvents(ctx, TenantReadParams{
		Actor: actor, TenantID: tenantID, Permission: authorization.TenantPermissionAuditRead,
		Query: withSentinelLimit(query), AccessAuditID: accessAuditID, Audit: audit,
	})
	if err != nil {
		return Page{}, mapReadError(err)
	}
	return validatedPage(rows, query, &tenantID)
}

func (service *Service) VerifyTenant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	audit authorization.AuditContext,
) (Verification, error) {
	if !validTenantAudit(audit) {
		return Verification{}, ErrInvalidInput
	}
	if !validTenantActor(actor, tenantID) {
		return Verification{}, ErrForbidden
	}
	if err := service.requireTenantAuditRead(ctx, actor, tenantID); err != nil {
		return Verification{}, err
	}
	accessAuditID, err := service.newAuditID()
	if err != nil {
		return Verification{}, err
	}
	verification, err := service.repository.VerifyTenantChain(ctx, TenantVerifyParams{
		Actor: actor, TenantID: tenantID, Permission: authorization.TenantPermissionAuditRead,
		AccessAuditID: accessAuditID, Audit: audit,
	})
	if err != nil {
		return Verification{}, mapReadError(err)
	}
	if !validVerification(verification, service.now().UTC()) {
		return Verification{}, ErrUnavailable
	}
	return cloneVerification(verification), nil
}

func (service *Service) ListPlatform(
	ctx context.Context,
	session authentication.Session,
	query Query,
	event authentication.EventContext,
) (Page, error) {
	query, err := normalizePlatformQuery(query)
	if err != nil || !validPlatformEvent(event) {
		return Page{}, ErrInvalidInput
	}
	if err := service.requirePlatformAuditRead(session); err != nil {
		return Page{}, err
	}
	accessAuditID, err := service.newAuditID()
	if err != nil {
		return Page{}, err
	}
	rows, err := service.repository.ListPlatformEvents(ctx, PlatformReadParams{
		Session: session, Permission: authorization.PermissionPlatformAuditRead,
		Query: withSentinelLimit(query), AccessAuditID: accessAuditID, Event: event,
	})
	if err != nil {
		return Page{}, mapReadError(err)
	}
	return validatedPage(rows, query, nil)
}

func (service *Service) VerifyPlatform(
	ctx context.Context,
	session authentication.Session,
	event authentication.EventContext,
) (Verification, error) {
	if !validPlatformEvent(event) {
		return Verification{}, ErrInvalidInput
	}
	if err := service.requirePlatformAuditRead(session); err != nil {
		return Verification{}, err
	}
	accessAuditID, err := service.newAuditID()
	if err != nil {
		return Verification{}, err
	}
	verification, err := service.repository.VerifyPlatformChain(ctx, PlatformVerifyParams{
		Session: session, Permission: authorization.PermissionPlatformAuditRead,
		AccessAuditID: accessAuditID, Event: event,
	})
	if err != nil {
		return Verification{}, mapReadError(err)
	}
	if !validVerification(verification, service.now().UTC()) {
		return Verification{}, ErrUnavailable
	}
	return cloneVerification(verification), nil
}

func (service *Service) requireTenantAuditRead(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) error {
	authority, err := service.resolver.ResolveAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		return mapReadError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != actor.UserID ||
		service.evaluator.RequireTenant(
			authority,
			authorization.TenantPermissionAuditRead,
			authorization.ResourceContext{TenantID: tenantID},
		) != nil {
		return ErrForbidden
	}
	return nil
}

func (service *Service) requirePlatformAuditRead(session authentication.Session) error {
	if !validPlatformSession(session, service.now().UTC()) ||
		service.evaluator.Require(session.Permissions, authorization.PermissionPlatformAuditRead) != nil {
		return ErrForbidden
	}
	return nil
}

func (service *Service) newAuditID() (uuid.UUID, error) {
	identifier, err := service.newID()
	if err != nil || !validUUIDv7(identifier) {
		return uuid.Nil, ErrUnavailable
	}
	return identifier, nil
}

func normalizeQuery(query Query) (Query, error) {
	if query.Limit == 0 {
		query.Limit = defaultPageSize
	}
	if query.Limit < 1 || query.Limit > maximumPageSize ||
		query.AfterSequence > math.MaxInt64 ||
		query.OccurredFrom != nil && query.OccurredFrom.IsZero() ||
		query.OccurredBefore != nil && query.OccurredBefore.IsZero() ||
		query.OccurredFrom != nil && query.OccurredBefore != nil && !query.OccurredFrom.Before(*query.OccurredBefore) ||
		query.ActorType != nil && !knownActorType(*query.ActorType) ||
		query.Outcome != nil && !knownOutcome(*query.Outcome) ||
		query.ActorUserID != nil && query.ActorServiceAccountID != nil ||
		!validOptionalUUID(query.ActorUserID) || !validOptionalUUID(query.ActorServiceAccountID) ||
		!validOptionalUUID(query.ResourceID) || !validOptionalUUID(query.RequestID) ||
		!validOptionalUUID(query.CorrelationID) {
		return Query{}, ErrInvalidInput
	}
	if query.ActorType != nil {
		switch *query.ActorType {
		case ActorUser:
			if query.ActorServiceAccountID != nil {
				return Query{}, ErrInvalidInput
			}
		case ActorServiceAccount:
			if query.ActorUserID != nil {
				return Query{}, ErrInvalidInput
			}
		case ActorSystem:
			if query.ActorUserID != nil || query.ActorServiceAccountID != nil {
				return Query{}, ErrInvalidInput
			}
		}
	}
	query.ActionPrefix = strings.TrimSpace(query.ActionPrefix)
	query.ResourceType = strings.TrimSpace(query.ResourceType)
	query.Search = strings.TrimSpace(query.Search)
	if query.ActionPrefix != "" && !validStableKey(query.ActionPrefix, 128) ||
		query.ResourceType != "" && !validStableKey(query.ResourceType, 128) ||
		!validSearch(query.Search) {
		return Query{}, ErrInvalidInput
	}
	if query.OccurredFrom != nil {
		value := query.OccurredFrom.UTC()
		query.OccurredFrom = &value
	}
	if query.OccurredBefore != nil {
		value := query.OccurredBefore.UTC()
		query.OccurredBefore = &value
	}
	return query, nil
}

func normalizePlatformQuery(query Query) (Query, error) {
	query, err := normalizeQuery(query)
	if err != nil || query.ActorServiceAccountID != nil {
		return Query{}, ErrInvalidInput
	}
	return query, nil
}

func withSentinelLimit(query Query) Query {
	query.Limit++
	return query
}

func validatedPage(rows []Event, query Query, tenantID *uuid.UUID) (Page, error) {
	if len(rows) > query.Limit+1 {
		return Page{}, ErrUnavailable
	}
	previousSequence := query.AfterSequence
	var previous *Event
	for index := range rows {
		event := &rows[index]
		if err := validateEvent(*event, tenantID); err != nil || event.Sequence <= previousSequence ||
			!eventMatchesQuery(*event, query) {
			return Page{}, ErrUnavailable
		}
		if previous != nil && event.Sequence == previous.Sequence+1 &&
			subtle.ConstantTimeCompare([]byte(event.PreviousHash), []byte(previous.EventHash)) != 1 {
			return Page{}, ErrUnavailable
		}
		previousSequence = event.Sequence
		previous = event
	}
	page := Page{Items: rows}
	if len(rows) > query.Limit {
		next := rows[query.Limit-1].Sequence
		page.Items = rows[:query.Limit]
		page.NextSequence = &next
	}
	page.Items = cloneEvents(page.Items)
	return page, nil
}

func cloneEvents(events []Event) []Event {
	cloned := slices.Clone(events)
	for index := range cloned {
		cloned[index].TenantID = clonePointer(cloned[index].TenantID)
		cloned[index].ActorUserID = clonePointer(cloned[index].ActorUserID)
		cloned[index].ActorServiceAccountID = clonePointer(cloned[index].ActorServiceAccountID)
		cloned[index].ImpersonatedByUserID = clonePointer(cloned[index].ImpersonatedByUserID)
		cloned[index].ResourceID = clonePointer(cloned[index].ResourceID)
		cloned[index].RequestID = clonePointer(cloned[index].RequestID)
		cloned[index].CorrelationID = clonePointer(cloned[index].CorrelationID)
		cloned[index].IPAddress = clonePointer(cloned[index].IPAddress)
		cloned[index].UserAgent = clonePointer(cloned[index].UserAgent)
		cloned[index].AuthenticationMethod = clonePointer(cloned[index].AuthenticationMethod)
		cloned[index].Reason = clonePointer(cloned[index].Reason)
		cloned[index].Before = slices.Clone(cloned[index].Before)
		cloned[index].After = slices.Clone(cloned[index].After)
		cloned[index].Metadata = slices.Clone(cloned[index].Metadata)
	}
	return cloned
}

func validVerification(verification Verification, now time.Time) bool {
	if now.IsZero() || verification.EventCount > math.MaxInt64 || verification.LastSequence > math.MaxInt64 ||
		verification.VerifiedAt.IsZero() ||
		verification.VerifiedAt.Before(now.Add(-5*time.Minute)) ||
		verification.VerifiedAt.After(now.Add(2*time.Minute)) ||
		verification.EventCount > verification.LastSequence {
		return false
	}
	if verification.FirstInvalidSequence != nil &&
		(*verification.FirstInvalidSequence == 0 || *verification.FirstInvalidSequence > verification.LastSequence) {
		return false
	}
	expectedValid := verification.HeadValid && verification.FirstInvalidSequence == nil &&
		verification.EventCount == verification.LastSequence
	return verification.Valid == expectedValid
}

func cloneVerification(verification Verification) Verification {
	verification.FirstInvalidSequence = clonePointer(verification.FirstInvalidSequence)
	return verification
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func validateEvent(event Event, tenantID *uuid.UUID) error {
	if !validUUIDv7(event.ID) || event.Sequence == 0 || event.Sequence > math.MaxInt64 || event.OccurredAt.IsZero() ||
		!knownActorType(event.ActorType) || !knownOutcome(event.Outcome) ||
		!validStableKey(event.Action, 128) || !validStableKey(event.ResourceType, 128) ||
		!validOptionalUUID(event.ActorUserID) || !validOptionalUUID(event.ActorServiceAccountID) ||
		!validOptionalUUID(event.ImpersonatedByUserID) || !validOptionalUUID(event.ResourceID) ||
		!validOptionalUUID(event.RequestID) || !validOptionalUUID(event.CorrelationID) ||
		!validOptionalAddress(event.IPAddress) || !validOptionalText(event.UserAgent, 1_024) ||
		!validOptionalAuthenticationMethod(event.AuthenticationMethod) || !validOptionalAuditReason(event.Reason) ||
		!hashPattern.MatchString(event.PreviousHash) || !hashPattern.MatchString(event.EventHash) {
		return ErrUnavailable
	}
	platform := tenantID == nil
	if platform {
		if event.TenantID != nil || event.ActorServiceAccountID != nil || event.ImpersonatedByUserID != nil {
			return ErrUnavailable
		}
	} else if event.TenantID == nil || *event.TenantID != *tenantID {
		return ErrUnavailable
	}
	switch event.ActorType {
	case ActorUser:
		if event.ActorUserID == nil || event.ActorServiceAccountID != nil {
			return ErrUnavailable
		}
	case ActorServiceAccount:
		if event.ActorUserID != nil || (!platform && event.ActorServiceAccountID == nil) ||
			(platform && event.ActorServiceAccountID != nil) || event.ImpersonatedByUserID != nil {
			return ErrUnavailable
		}
	case ActorSystem:
		if event.ActorUserID != nil || event.ActorServiceAccountID != nil || event.ImpersonatedByUserID != nil {
			return ErrUnavailable
		}
	}
	if event.Sequence == 1 && event.PreviousHash != zeroAuditHash {
		return ErrUnavailable
	}
	for _, document := range []struct {
		value    json.RawMessage
		maxBytes int
	}{
		{event.Before, maximumDocumentBytes},
		{event.After, maximumDocumentBytes},
		{event.Metadata, maximumMetadataBytes},
	} {
		if err := validateJSONDocument(document.value, document.maxBytes); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func eventMatchesQuery(event Event, query Query) bool {
	if query.OccurredFrom != nil && event.OccurredAt.Before(*query.OccurredFrom) ||
		query.OccurredBefore != nil && !event.OccurredAt.Before(*query.OccurredBefore) ||
		query.ActorType != nil && event.ActorType != *query.ActorType ||
		query.ActorUserID != nil && !sameOptionalUUID(event.ActorUserID, query.ActorUserID) ||
		query.ActorServiceAccountID != nil && !sameOptionalUUID(event.ActorServiceAccountID, query.ActorServiceAccountID) ||
		query.ActionPrefix != "" && event.Action != query.ActionPrefix && !strings.HasPrefix(event.Action, query.ActionPrefix+".") ||
		query.ResourceType != "" && event.ResourceType != query.ResourceType ||
		query.ResourceID != nil && !sameOptionalUUID(event.ResourceID, query.ResourceID) ||
		query.RequestID != nil && !sameOptionalUUID(event.RequestID, query.RequestID) ||
		query.CorrelationID != nil && !sameOptionalUUID(event.CorrelationID, query.CorrelationID) ||
		query.Outcome != nil && event.Outcome != *query.Outcome {
		return false
	}
	if query.Search == "" {
		return true
	}
	needle := strings.ToLower(query.Search)
	return strings.Contains(strings.ToLower(event.Action), needle) ||
		strings.Contains(strings.ToLower(event.ResourceType), needle) ||
		event.Reason != nil && strings.Contains(strings.ToLower(*event.Reason), needle)
}

func validateJSONDocument(raw json.RawMessage, maximum int) error {
	if len(raw) == 0 {
		return ErrUnavailable
	}
	if len(raw) > maximum || !json.Valid(raw) {
		return ErrUnavailable
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if value == nil {
		return ErrUnavailable
	}
	if _, object := value.(map[string]any); !object {
		return ErrUnavailable
	}
	nodes := 0
	if !safeJSONValue(value, 1, &nodes) {
		return ErrUnavailable
	}
	return nil
}

func safeJSONValue(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > maximumJSONDepth || *nodes > maximumJSONNodes {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			canonicalKey := canonicalJSONKey(key)
			if prohibitedJSONKey(canonicalKey) || !validSafeSensitiveValue(canonicalKey, child) ||
				!safeJSONValue(child, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, child := range typed {
			if !safeJSONValue(child, depth+1, nodes) {
				return false
			}
		}
	case string, json.Number, bool, nil:
		return true
	default:
		return false
	}
	return true
}

func prohibitedJSONKey(value string) bool {
	if safeSensitiveKey(value) {
		return false
	}
	if _, prohibited := prohibitedKeys[value]; prohibited {
		return true
	}
	for _, fragment := range sensitiveKeyFragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func safeSensitiveKey(value string) bool {
	for _, catalog := range safeSensitiveKeyCatalogs {
		if _, safe := catalog[value]; safe {
			return true
		}
	}
	return false
}

func validSafeSensitiveValue(key string, value any) bool {
	if _, expected := safeSensitiveBooleanKeys[key]; expected {
		_, valid := value.(bool)
		return valid
	}
	if _, expected := safeSensitiveIdentifierKeys[key]; expected {
		if value == nil {
			return true
		}
		identifier, valid := value.(string)
		if !valid {
			return false
		}
		parsed, err := uuid.Parse(identifier)
		return err == nil && validUUIDv7(parsed)
	}
	if _, expected := safeSensitiveIntegerKeys[key]; expected {
		number, valid := value.(json.Number)
		if !valid {
			return false
		}
		integer, err := number.Int64()
		return err == nil && integer >= 0
	}
	if _, expected := safeSensitiveKindKeys[key]; expected {
		kind, valid := value.(string)
		return valid && validStableKey(kind, 64)
	}
	return true
}

func canonicalJSONKey(value string) string {
	var result strings.Builder
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			result.WriteRune(character)
		}
	}
	return result.String()
}

func validTenantActor(actor authorization.Actor, tenantID uuid.UUID) bool {
	return validUUIDv7(actor.UserID) && validUUIDv7(actor.SessionID) && validUUIDv7(tenantID) &&
		actor.ActiveTenantID == tenantID && stableAuthenticationMethod(actor.AuthenticationMethod)
}

func validTenantAudit(audit authorization.AuditContext) bool {
	return validUUIDv7(audit.RequestID) && validUUIDv7(audit.CorrelationID) &&
		audit.RemoteAddress.IsValid() && validText(audit.UserAgent, 1_024)
}

func validPlatformSession(session authentication.Session, now time.Time) bool {
	return validUUIDv7(session.ID) && validUUIDv7(session.User.ID) &&
		!now.IsZero() && session.RevokedAt == nil && !session.CreatedAt.IsZero() &&
		!session.LastSeenAt.Before(session.CreatedAt) && !now.Before(session.LastSeenAt) &&
		now.Before(session.IdleExpiresAt) && now.Before(session.AbsoluteExpiresAt) &&
		stableAuthenticationMethod(session.AuthenticationMethod)
}

func validPlatformEvent(event authentication.EventContext) bool {
	return validUUIDv7(event.RequestID) && validUUIDv7(event.CorrelationID) &&
		event.RemoteAddress.IsValid() && validText(event.UserAgent, 1_024)
}

func stableAuthenticationMethod(value string) bool {
	return authenticationMethodPattern.MatchString(value)
}

func validStableKey(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && stableKeyPattern.MatchString(value)
}

func validSearch(value string) bool {
	if value == "" {
		return true
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximumSearchRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\t' {
			return false
		}
	}
	return true
}

func validOptionalText(value *string, maximum int) bool {
	return value == nil || validText(*value, maximum)
}

// Platform lifecycle reasons are persisted with an octet-length boundary.
// Validate that exact representation contract here so a successfully committed
// 1025-2048 byte reason never makes the audit read surface fail closed.
func validOptionalAuditReason(value *string) bool {
	if value == nil {
		return true
	}
	reason := *value
	if reason == "" || !utf8.ValidString(reason) || len(reason) > 2_048 || strings.TrimSpace(reason) != reason {
		return false
	}
	for _, character := range reason {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validOptionalAuthenticationMethod(value *string) bool {
	return value == nil || stableAuthenticationMethod(*value)
}

func validOptionalAddress(value *netip.Addr) bool {
	return value == nil || value.IsValid()
}

func validOptionalUUID(value *uuid.UUID) bool {
	return value == nil || *value != uuid.Nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	return left != nil && right != nil && *left == *right
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && (value[8]&0xc0) == 0x80
}

func knownActorType(value ActorType) bool {
	return value == ActorUser || value == ActorServiceAccount || value == ActorSystem
}

func knownOutcome(value Outcome) bool {
	return value == OutcomeSuccess || value == OutcomeFailure || value == OutcomeDenied
}

func mapReadError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrForbidden), errors.Is(err, authorization.ErrForbidden),
		errors.Is(err, authentication.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, ErrInvalidInput), errors.Is(err, authorization.ErrInvalidInput),
		errors.Is(err, authentication.ErrInvalidInput):
		return ErrInvalidInput
	default:
		return ErrUnavailable
	}
}
