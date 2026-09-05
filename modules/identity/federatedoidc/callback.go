package federatedoidc

import (
	"context"
	"crypto/sha256"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

type parsedCallback struct {
	state         []byte
	code          []byte
	issuer        string
	providerError bool
}

func (flow *Flow) claimCallback(
	ctx context.Context,
	request callbackRequest,
) (*ClaimedAuthorization, error) {
	configuration, scopes, err := flow.normalizeConfiguration(request.Configuration)
	if err != nil || !validOpaque(request.BrowserHandle) {
		return nil, ErrCallbackRejected
	}
	callback, err := flow.parseCallback(request.RawQuery)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	defer clear(callback.state)
	defer clear(callback.code)
	if callback.issuer != "" && callback.issuer != configuration.Discovery.Issuer() {
		return nil, ErrCallbackRejected
	}
	now, ok := flow.currentTime()
	if !ok {
		return nil, ErrCallbackRejected
	}
	operationCtx, cancel, err := flow.operationContext(ctx)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	defer cancel()
	attemptID, err := generateTransactionID(flow.random)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	claim := TransactionClaim{
		AttemptID:               attemptID,
		StateDigest:             sha256.Sum256(callback.state),
		BrowserDigest:           sha256.Sum256(request.BrowserHandle),
		AuthorizationCodeDigest: sha256.Sum256(callback.code),
		ClaimedAt:               now,
	}
	record, repositoryErr := flow.claimTransaction(operationCtx, claim)
	if repositoryErr != nil {
		return nil, ErrCallbackRejected
	}
	defer clear(record.Verifier.Ciphertext)
	if !validClaimedTransaction(record, claim, configuration, scopes, flow.policy.TransactionTTL) {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureStaleConfiguration, TransactionFailed)
		return nil, ErrCallbackRejected
	}
	if callback.providerError {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureProviderResponse, TransactionFailed)
		return nil, ErrCallbackRejected
	}
	if !now.Before(record.ExpiresAt) {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureExpired, TransactionExpired)
		return nil, ErrCallbackRejected
	}
	claimed := &ClaimedAuthorization{
		owner:         flow,
		record:        cloneClaimedTransaction(record),
		configuration: configuration,
		code:          append([]byte(nil), callback.code...),
		audit:         claim.Audit,
	}
	claimed.stage.Store(claimedStageReady)
	return claimed, nil
}

// ClaimCallbackResolved claims the one-time browser transaction before
// resolving any tenant-owned configuration. This is the public/pre-auth path:
// the callback supplies only state, browser binding, and the provider query;
// tenant context is derived from the claimed transaction pins.
func (flow *Flow) ClaimCallbackResolved(
	ctx context.Context,
	request ResolvedCallbackRequest,
	resolver CallbackConfigurationResolver,
) (*ClaimedAuthorization, error) {
	if resolver == nil || !validOpaque(request.BrowserHandle) {
		return nil, ErrCallbackRejected
	}
	callback, err := flow.parseCallback(request.RawQuery)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	defer clear(callback.state)
	defer clear(callback.code)
	now, ok := flow.currentTime()
	if !ok {
		return nil, ErrCallbackRejected
	}
	operationCtx, cancel, err := flow.operationContext(ctx)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	defer cancel()
	attemptID, err := generateTransactionID(flow.random)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	claim := TransactionClaim{
		AttemptID:               attemptID,
		StateDigest:             sha256.Sum256(callback.state),
		BrowserDigest:           sha256.Sum256(request.BrowserHandle),
		AuthorizationCodeDigest: sha256.Sum256(callback.code),
		ClaimedAt:               now,
		Audit:                   request.Audit,
	}
	record, repositoryErr := flow.claimTransaction(operationCtx, claim)
	if repositoryErr != nil {
		return nil, ErrCallbackRejected
	}
	defer clear(record.Verifier.Ciphertext)
	if !validClaimedEnvelope(record, claim, flow.policy.TransactionTTL) {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureStaleConfiguration, TransactionFailed)
		return nil, ErrCallbackRejected
	}
	if callback.providerError {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureProviderResponse, TransactionFailed)
		return nil, ErrCallbackRejected
	}
	if !now.Before(record.ExpiresAt) {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureExpired, TransactionExpired)
		return nil, ErrCallbackRejected
	}
	configuration, resolveErr := resolver.ResolveOIDCCallbackConfiguration(operationCtx, CallbackConfigurationLookup{
		TransactionID: record.ID, ExpectedVersion: record.Version, Pins: record.Pins,
		ReturnPath: record.ReturnPath,
	})
	configuration, scopes, normalizeErr := flow.normalizeConfiguration(configuration)
	if resolveErr != nil || normalizeErr != nil ||
		callback.issuer != "" && callback.issuer != configuration.Discovery.Issuer() ||
		!validClaimedTransaction(record, claim, configuration, scopes, flow.policy.TransactionTTL) {
		flow.failTransaction(operationCtx, record, claim.Audit, now, FailureStaleConfiguration, TransactionFailed)
		return nil, ErrCallbackRejected
	}
	claimed := &ClaimedAuthorization{
		owner:         flow,
		record:        cloneClaimedTransaction(record),
		configuration: configuration,
		code:          append([]byte(nil), callback.code...),
		audit:         claim.Audit,
	}
	claimed.stage.Store(claimedStageReady)
	return claimed, nil
}

// AbortClaimedAuthorization terminally annotates a claimed transaction when
// a post-claim application dependency (secret load, UserInfo, planning, or
// atomic apply) fails. It is one-use and never exposes the underlying error.
func (flow *Flow) AbortClaimedAuthorization(
	ctx context.Context,
	claimed *ClaimedAuthorization,
) error {
	if flow == nil || claimed == nil || claimed.owner != flow {
		return ErrCallbackRejected
	}
	operationCtx, cancel, err := flow.operationContext(ctx)
	if err != nil {
		return ErrCallbackRejected
	}
	defer cancel()
	for {
		stage := claimed.stage.Load()
		switch stage {
		case claimedStageReady, claimedStageExchanged, claimedStageVerified, claimedStageAbortRetry:
			if !claimed.stage.CompareAndSwap(stage, claimedStageAborting) {
				continue
			}
			if stage != claimedStageAbortRetry {
				now, ok := flow.currentTime()
				if !ok {
					claimed.stage.Store(stage)
					return ErrCallbackRejected
				}
				claimed.abortFailure = TransactionFailure{
					ID: claimed.record.ID, ExpectedVersion: claimed.record.Version, FailedAt: now,
					Reason: FailureIdentityApplication, State: TransactionFailed, Audit: claimed.audit,
				}
			}
		default:
			return ErrCallbackRejected
		}
		break
	}
	clear(claimed.code)
	claimed.code = nil
	clear(claimed.record.Verifier.Ciphertext)
	claimed.record.Verifier = ProtectedVerifier{}
	claimed.configuration = AuthorizationConfiguration{}
	if err = flow.transactions.Fail(operationCtx, claimed.abortFailure); err != nil {
		claimed.stage.Store(claimedStageAbortRetry)
		return ErrCallbackRejected
	}
	claimed.stage.Store(claimedStageFailed)
	return nil
}

func (flow *Flow) claimTransaction(
	ctx context.Context,
	claim TransactionClaim,
) (ClaimedTransaction, error) {
	for range 2 {
		record, err := flow.transactions.Claim(ctx, claim)
		if err == nil {
			return record, err
		}
		clear(record.Verifier.Ciphertext)
		if ctx.Err() != nil {
			return ClaimedTransaction{}, err
		}
	}
	return ClaimedTransaction{}, ErrCallbackRejected
}

func (flow *Flow) parseCallback(rawQuery string) (parsedCallback, error) {
	if flow == nil || rawQuery == "" || len(rawQuery) > flow.policy.Limits.MaxCallbackQueryBytes ||
		strings.HasPrefix(rawQuery, "?") || !utf8.ValidString(rawQuery) ||
		!strictCallbackMemberNames(rawQuery) {
		return parsedCallback{}, ErrCallbackRejected
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) == 0 || len(values) > 8 {
		return parsedCallback{}, ErrCallbackRejected
	}
	allowed := map[string]struct{}{
		"code": {}, "state": {}, "error": {}, "error_description": {},
		"error_uri": {}, "iss": {}, "session_state": {},
	}
	for name, entries := range values {
		if _, ok := allowed[name]; !ok || len(entries) != 1 || name == "" ||
			len(entries[0]) > maximumAuthorizationCodeBytes || !utf8.ValidString(entries[0]) {
			return parsedCallback{}, ErrCallbackRejected
		}
	}
	stateValues, statePresent := values["state"]
	if !statePresent || !validOpaque([]byte(stateValues[0])) {
		return parsedCallback{}, ErrCallbackRejected
	}
	codeValues, codePresent := values["code"]
	errorValues, errorPresent := values["error"]
	if codePresent == errorPresent {
		return parsedCallback{}, ErrCallbackRejected
	}
	if !errorPresent && (values["error_description"] != nil || values["error_uri"] != nil) {
		return parsedCallback{}, ErrCallbackRejected
	}
	result := parsedCallback{state: []byte(stateValues[0]), providerError: errorPresent}
	if codePresent {
		if !validAuthorizationCode(codeValues[0]) {
			clear(result.state)
			return parsedCallback{}, ErrCallbackRejected
		}
		result.code = []byte(codeValues[0])
	} else if len(errorValues[0]) == 0 || !validSafeText(errorValues[0], 256) {
		clear(result.state)
		return parsedCallback{}, ErrCallbackRejected
	}
	if descriptions := values["error_description"]; descriptions != nil &&
		!validSafeText(descriptions[0], 1024) {
		clear(result.state)
		clear(result.code)
		return parsedCallback{}, ErrCallbackRejected
	}
	if errorURIs := values["error_uri"]; errorURIs != nil && !validSafeText(errorURIs[0], 2048) {
		clear(result.state)
		clear(result.code)
		return parsedCallback{}, ErrCallbackRejected
	}
	if sessions := values["session_state"]; sessions != nil && !validSafeText(sessions[0], 1024) {
		clear(result.state)
		clear(result.code)
		return parsedCallback{}, ErrCallbackRejected
	}
	if issuerValues := values["iss"]; issuerValues != nil {
		if issuerValues[0] == "" || len(issuerValues[0]) > maximumMetadataStringBytes {
			clear(result.state)
			clear(result.code)
			return parsedCallback{}, ErrCallbackRejected
		}
		result.issuer = issuerValues[0]
	}
	return result, nil
}

func strictCallbackMemberNames(rawQuery string) bool {
	for _, pair := range strings.Split(rawQuery, "&") {
		name, _, found := strings.Cut(pair, "=")
		if !found {
			return false
		}
		switch name {
		case "code", "state", "error", "error_description", "error_uri", "iss", "session_state":
		default:
			return false
		}
	}
	return true
}

func validAuthorizationCode(value string) bool {
	if value == "" || len(value) > maximumAuthorizationCodeBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validSafeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || isDirectionalControl(character) {
			return false
		}
	}
	return true
}

func validClaimedTransaction(
	record ClaimedTransaction,
	claim TransactionClaim,
	configuration AuthorizationConfiguration,
	scopes []string,
	transactionTTL time.Duration,
) bool {
	return validClaimedEnvelope(record, claim, transactionTTL) &&
		record.Pins == transactionPins(configuration) && record.ClientID == configuration.ClientID &&
		record.RedirectURI == configuration.RedirectURI &&
		record.PostLogoutRedirectURI == configuration.PostLogoutRedirectURI &&
		validReturnPath(record.ReturnPath) &&
		slices.Equal(record.Scopes, scopes) && record.AllowRefreshToken == configuration.AllowRefreshToken &&
		record.UseUserInfo == configuration.UseUserInfo &&
		record.ClaimedAt.Before(record.ExpiresAt)
}

func validClaimedEnvelope(record ClaimedTransaction, claim TransactionClaim, transactionTTL time.Duration) bool {
	direct := record.Pins.Authority == DirectPlatformCeremonyAuthority
	return record.ID != (TransactionID{}) && record.State == TransactionClaimed && record.Version == 2 &&
		(direct && (record.MaterialID == (identity.EntityID{}) || validMaterialID(record.MaterialID)) ||
			!direct && validMaterialID(record.MaterialID)) &&
		record.ClaimAttemptID != (TransactionID{}) && record.ClaimAttemptID == claim.AttemptID &&
		(!direct || equalDigest(record.AuthorizationCodeDigest, claim.AuthorizationCodeDigest)) &&
		transactionTTL >= minimumTransactionTTL && transactionTTL <= maximumTransactionTTL &&
		equalDigest(record.StateDigest, claim.StateDigest) &&
		equalDigest(record.BrowserDigest, claim.BrowserDigest) &&
		record.NonceDigest != ([sha256.Size]byte{}) && validProtectedVerifier(record.Verifier) &&
		validTransactionPinsShape(record.Pins) &&
		validReturnPath(record.ReturnPath) && validFlowInstant(record.CreatedAt) &&
		validFlowInstant(record.ExpiresAt) && validFlowInstant(record.ClaimedAt) &&
		record.ClaimedAt.Equal(claim.ClaimedAt) && record.ExpiresAt.Equal(record.CreatedAt.Add(transactionTTL)) &&
		!record.ClaimedAt.Before(record.CreatedAt)
}

func validMaterialID(value identity.EntityID) bool {
	return value != (identity.EntityID{}) && value[6]>>4 == 7 && value[8]&0xc0 == 0x80
}

func validTransactionPinsShape(pins TransactionPins) bool {
	return validCeremonyAuthority(
		pins.Authority, pins.Provider, pins.BindingID, pins.Admission, pins.BindingRevision,
		pins.MappingRevision, pins.AuthorizationRevision, pins.PlatformLoginRevision,
	) && validTransactionPinExtensions(pins) &&
		validPersistentRevision(pins.ProviderRevision) &&
		validPersistentRevision(pins.ConfigurationRevision) &&
		validPersistentRevision(pins.SecurityRevision) &&
		validPersistentRevision(pins.AssurancePolicyRevision) &&
		validPersistentRevision(pins.ClientSecretRevision) && validPersistentRevision(pins.DiscoveryRevision) &&
		pins.DiscoveryDigest != ([sha256.Size]byte{}) &&
		validPersistentRevision(pins.JWKSRevision) && pins.JWKSDigest != ([sha256.Size]byte{})
}

func validTransactionPinExtensions(pins TransactionPins) bool {
	zeroID := identity.EntityID{}
	switch pins.Authority {
	case TenantCeremonyAuthority:
		return pins.PlanRevision == 0 && pins.PlatformFloorPolicyID == zeroID &&
			pins.PlatformFloorRevision == 0
	case DirectPlatformCeremonyAuthority:
		return validPersistentRevision(pins.PlanRevision) && pins.PlatformFloorPolicyID != zeroID &&
			validPersistentRevision(pins.PlatformFloorRevision)
	default:
		return false
	}
}

func cloneClaimedTransaction(source ClaimedTransaction) ClaimedTransaction {
	result := source
	result.Verifier = cloneProtectedVerifier(source.Verifier)
	result.Scopes = append([]string(nil), source.Scopes...)
	return result
}

func (flow *Flow) failTransaction(
	ctx context.Context,
	record ClaimedTransaction,
	audit TransactionAuditContext,
	now time.Time,
	reason TransactionFailureReason,
	state TransactionState,
) {
	if flow == nil || flow.transactions == nil || record.ID == (TransactionID{}) || record.Version == 0 ||
		ctx == nil || !validFlowInstant(now) || !validFailureReason(reason) ||
		state != TransactionFailed && state != TransactionExpired {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), flow.policy.OperationTimeout)
	defer cancel()
	failure := TransactionFailure{
		ID: record.ID, ExpectedVersion: record.Version, FailedAt: now, Reason: reason, State: state,
		Audit: audit,
	}
	for range 2 {
		if err := flow.transactions.Fail(cleanup, failure); err == nil || cleanup.Err() != nil {
			return
		}
	}
}

func validFailureReason(reason TransactionFailureReason) bool {
	switch reason {
	case FailureProviderResponse, FailureStaleConfiguration, FailureExpired,
		FailureTokenExchange, FailureTokenValidation, FailureIdentityApplication:
		return true
	default:
		return false
	}
}
