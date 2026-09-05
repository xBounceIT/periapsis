package federatedoidc

import (
	"strconv"
	"time"
)

func (state TransactionState) String() string   { return safeTransactionState(state) }
func (state TransactionState) GoString() string { return state.String() }

func (reason TransactionFailureReason) String() string   { return safeFailureReason(reason) }
func (reason TransactionFailureReason) GoString() string { return reason.String() }

func (authority CeremonyAuthority) String() string   { return safeCeremonyAuthority(authority) }
func (authority CeremonyAuthority) GoString() string { return authority.String() }

func (endpoint CallbackEndpoint) String() string   { return safeCallbackEndpoint(endpoint) }
func (endpoint CallbackEndpoint) GoString() string { return endpoint.String() }

func (kind EndpointKind) String() string   { return safeEndpointKind(kind) }
func (kind EndpointKind) GoString() string { return kind.String() }

func (category TokenEndpointCategory) String() string   { return safeTokenEndpointCategory(category) }
func (category TokenEndpointCategory) GoString() string { return category.String() }

func (kind TokenKind) String() string   { return safeTokenKind(kind) }
func (kind TokenKind) GoString() string { return kind.String() }

func (field ProfileField) String() string   { return safeProfileField(field) }
func (field ProfileField) GoString() string { return field.String() }

func (limits FlowLimits) String() string {
	return "federatedoidc.FlowLimits{" +
		"callback=" + positive(limits.MaxCallbackQueryBytes) +
		",token_response=" + positive(limits.MaxTokenResponseBytes) +
		",compact_token=" + positive(limits.MaxCompactTokenBytes) +
		",token_value=" + positive(limits.MaxTokenValueBytes) +
		",claims=" + positive(limits.MaxClaimValueBytes) +
		"}"
}
func (limits FlowLimits) GoString() string { return limits.String() }

func (policy FlowPolicy) String() string {
	return "federatedoidc.FlowPolicy{" +
		"transaction_ttl=" + positiveDuration(policy.TransactionTTL) +
		",operation_timeout=" + positiveDuration(policy.OperationTimeout) +
		",clock_skew_configured=" + strconv.FormatBool(policy.ClockSkew >= 0) +
		",limits=" + strconv.Quote(policy.Limits.String()) +
		"}"
}
func (policy FlowPolicy) GoString() string { return policy.String() }

func (id TransactionID) String() string {
	return "federatedoidc.TransactionID{valid=" + strconv.FormatBool(id != (TransactionID{})) + "}"
}
func (id TransactionID) GoString() string { return id.String() }

func (pins TransactionPins) String() string {
	return "federatedoidc.TransactionPins{" +
		"authority=" + safeCeremonyAuthority(pins.Authority) +
		",provider=" + strconv.FormatBool(pins.ProviderRevision != 0) +
		",binding=" + strconv.FormatBool(pins.BindingRevision != 0) +
		",platform_login=" + strconv.FormatBool(pins.PlatformLoginRevision != 0) +
		",configuration=" + strconv.FormatBool(pins.ConfigurationRevision != 0) +
		",security=" + strconv.FormatBool(pins.SecurityRevision != 0) +
		",plan=" + strconv.FormatBool(pins.PlanRevision != 0) +
		",mapping=" + strconv.FormatBool(pins.MappingRevision != 0) +
		",authorization=" + strconv.FormatBool(pins.AuthorizationRevision != 0) +
		",assurance_policy=" + strconv.FormatBool(pins.AssurancePolicyRevision != 0) +
		",platform_floor=" + strconv.FormatBool(pins.PlatformFloorPolicyID != ([16]byte{})) +
		",credential=" + strconv.FormatBool(pins.ClientSecretRevision != 0) +
		",discovery=" + strconv.FormatBool(pins.DiscoveryRevision != 0) +
		",jwks=" + strconv.FormatBool(pins.JWKSRevision != 0) +
		"}"
}
func (pins TransactionPins) GoString() string { return pins.String() }

func (verifier ProtectedVerifier) String() string {
	return "federatedoidc.ProtectedVerifier{" +
		"key_version=" + strconv.FormatBool(verifier.KeyVersion != 0) +
		",ciphertext=" + strconv.FormatBool(len(verifier.Ciphertext) != 0) +
		"}"
}
func (verifier ProtectedVerifier) GoString() string { return verifier.String() }

func (protection TransactionProtectionContext) String() string {
	return "federatedoidc.TransactionProtectionContext{" +
		"authority=" + safeCeremonyAuthority(protection.Authority) +
		",transaction=" + strconv.FormatBool(protection.TransactionID != (TransactionID{})) +
		",provider=" + strconv.FormatBool(protection.Provider.ProviderID != ([16]byte{})) +
		",binding=" + strconv.FormatBool(protection.BindingID != ([16]byte{})) +
		",platform_login=" + strconv.FormatBool(protection.PlatformLoginRevision != 0) +
		"}"
}
func (protection TransactionProtectionContext) GoString() string { return protection.String() }

func (begin AuthorizationBegin) String() string {
	return "federatedoidc.AuthorizationBegin{" +
		"operation=" + strconv.FormatBool(begin.OperationRunID != ([16]byte{})) +
		",receipt=" + strconv.FormatBool(begin.ReceiptDigest != (StartReceiptDigest{})) +
		",network=" + strconv.FormatBool(begin.NetworkDigest != (NetworkThrottleDigest{})) +
		",account=" + strconv.FormatBool(begin.AccountDigest != (AccountThrottleDigest{})) +
		",provider=" + strconv.FormatBool(begin.ProviderDigest != (ProviderThrottleDigest{})) +
		",material=[REDACTED]}"
}
func (begin AuthorizationBegin) GoString() string { return begin.String() }

func (audit TransactionAuditContext) String() string {
	return "federatedoidc.TransactionAuditContext{" +
		"request=" + strconv.FormatBool(audit.RequestID != ([16]byte{})) +
		",correlation=" + strconv.FormatBool(audit.CorrelationID != ([16]byte{})) +
		",remote=" + strconv.FormatBool(audit.RemoteAddress.IsValid()) +
		",user_agent=" + strconv.FormatBool(audit.UserAgent != "") +
		",material=[REDACTED]}"
}
func (audit TransactionAuditContext) GoString() string { return audit.String() }

func (transaction PendingTransaction) String() string {
	return "federatedoidc.PendingTransaction{" +
		"id=" + strconv.Quote(transaction.ID.String()) +
		",material=" + strconv.FormatBool(transaction.MaterialID != ([16]byte{})) +
		",state=" + safeTransactionState(transaction.State) +
		",version=" + strconv.FormatBool(transaction.Version != 0) +
		",verifier=" + strconv.Quote(transaction.Verifier.String()) +
		",scopes=" + strconv.Itoa(len(transaction.Scopes)) +
		",refresh=" + strconv.FormatBool(transaction.AllowRefreshToken) +
		",userinfo=" + strconv.FormatBool(transaction.UseUserInfo) +
		"}"
}
func (transaction PendingTransaction) GoString() string { return transaction.String() }

func (request CreateTransactionRequest) String() string {
	return "federatedoidc.CreateTransactionRequest{" +
		"begin=" + strconv.Quote(request.Begin.String()) +
		",current=" + strconv.Quote(request.Current.String()) +
		",replacement=" + strconv.FormatBool(request.HasPreviousBrowserBinding) +
		",application_browser=" + strconv.FormatBool(request.ApplicationBrowserBindingDigest != ([32]byte{})) +
		",audit=" + strconv.Quote(request.Audit.String()) +
		"}"
}
func (request CreateTransactionRequest) GoString() string { return request.String() }

func (claim TransactionClaim) String() string {
	return "federatedoidc.TransactionClaim{attempt=" + strconv.FormatBool(claim.AttemptID != (TransactionID{})) +
		",state=true,browser=true,code_digest=true,audit=" + strconv.Quote(claim.Audit.String()) +
		",claimed_at=" +
		strconv.FormatBool(!claim.ClaimedAt.IsZero()) + "}"
}
func (claim TransactionClaim) GoString() string { return claim.String() }

func (transaction ClaimedTransaction) String() string {
	return "federatedoidc.ClaimedTransaction{pending=" +
		strconv.Quote(transaction.PendingTransaction.String()) +
		",attempt=" + strconv.FormatBool(transaction.ClaimAttemptID != (TransactionID{})) +
		",claimed_at=" + strconv.FormatBool(!transaction.ClaimedAt.IsZero()) + "}"
}
func (transaction ClaimedTransaction) GoString() string { return transaction.String() }

func (failure TransactionFailure) String() string {
	return "federatedoidc.TransactionFailure{" +
		"id=" + strconv.Quote(failure.ID.String()) +
		",version=" + strconv.FormatBool(failure.ExpectedVersion != 0) +
		",reason=" + safeFailureReason(failure.Reason) +
		",state=" + safeTransactionState(failure.State) +
		",audit=" + strconv.Quote(failure.Audit.String()) +
		"}"
}
func (failure TransactionFailure) GoString() string { return failure.String() }

func (completion TransactionCompletion) String() string {
	return "federatedoidc.TransactionCompletion{" +
		"id=" + strconv.Quote(completion.ID.String()) +
		",material=" + strconv.FormatBool(completion.MaterialID != ([16]byte{})) +
		",version=" + strconv.FormatBool(completion.ExpectedVersion != 0) +
		",pins=" + strconv.Quote(completion.Pins.String()) +
		",return_path=" + strconv.FormatBool(completion.ReturnPath != "") +
		"}"
}
func (completion TransactionCompletion) GoString() string { return completion.String() }

func (endpoint PinnedEndpoint) String() string {
	return "federatedoidc.PinnedEndpoint{kind=" + safeEndpointKind(endpoint.kind) +
		",valid=" + strconv.FormatBool(endpoint.valid) + "}"
}
func (endpoint PinnedEndpoint) GoString() string { return endpoint.String() }

func (request TokenExchangeRequest) String() string {
	return "federatedoidc.TokenExchangeRequest{" +
		"endpoint=" + strconv.Quote(request.Endpoint.String()) +
		",grant_type=" + strconv.FormatBool(request.GrantType == GrantAuthorizationCode) +
		",client_authentication=" + safeClientAuthentication(request.ClientAuthentication) +
		",client_id=" + strconv.FormatBool(request.ClientID != "") +
		",client_secret=" + strconv.FormatBool(len(request.ClientSecret) != 0) +
		",code=" + strconv.FormatBool(len(request.AuthorizationCode) != 0) +
		",redirect=" + strconv.FormatBool(request.RedirectURI != "") +
		",pkce=" + strconv.FormatBool(len(request.PKCEVerifier) != 0) +
		"}"
}
func (request TokenExchangeRequest) GoString() string { return request.String() }

func (response TokenEndpointResponse) String() string {
	return "federatedoidc.TokenEndpointResponse{" +
		"category=" + safeTokenEndpointCategory(response.Category) +
		",status=" + strconv.Itoa(response.StatusCode) +
		",media_type=" + strconv.FormatBool(response.MediaType != "") +
		",body=" + strconv.FormatBool(len(response.Body) != 0) +
		"}"
}
func (response TokenEndpointResponse) GoString() string { return response.String() }

func (credential ClientCredential) String() string {
	return "federatedoidc.ClientCredential{revision=" +
		strconv.FormatBool(credential.Revision != 0) +
		",secret=" + strconv.FormatBool(len(credential.Secret) != 0) + "}"
}
func (credential ClientCredential) GoString() string { return credential.String() }

func (options FlowOptions) String() string {
	return "federatedoidc.FlowOptions{" +
		"trust=" + strconv.FormatBool(options.Trust != nil) +
		",transactions=" + strconv.FormatBool(options.Transactions != nil) +
		",protector=" + strconv.FormatBool(options.VerifierProtector != nil) +
		",token_endpoint=" + strconv.FormatBool(options.TokenEndpoint != nil) +
		",redirect=" + strconv.FormatBool(options.RedirectURI != "") +
		",logout_redirect=" + strconv.FormatBool(options.PostLogoutRedirectURI != "") +
		",policy=" + strconv.Quote(options.Policy.String()) +
		"}"
}
func (options FlowOptions) GoString() string { return options.String() }

func (flow *Flow) String() string {
	return "federatedoidc.Flow{configured=" + strconv.FormatBool(flow != nil && flow.trust != nil) + "}"
}
func (flow *Flow) GoString() string { return flow.String() }

func (configuration AuthorizationConfiguration) String() string {
	return "federatedoidc.AuthorizationConfiguration{" +
		"authority=" + safeCeremonyAuthority(configuration.Authority) +
		",provider=" + strconv.FormatBool(configuration.ProviderRevision != 0) +
		",binding=" + strconv.FormatBool(configuration.BindingRevision != 0) +
		",platform_login=" + strconv.FormatBool(configuration.PlatformLoginRevision != 0) +
		",configuration=" + strconv.FormatBool(configuration.ConfigurationRevision != 0) +
		",security=" + strconv.FormatBool(configuration.SecurityRevision != 0) +
		",mapping=" + strconv.FormatBool(configuration.MappingRevision != 0) +
		",authorization=" + strconv.FormatBool(configuration.AuthorizationRevision != 0) +
		",assurance_policy=" + strconv.FormatBool(configuration.AssurancePolicyRevision != 0) +
		",credential=" + strconv.FormatBool(configuration.ClientSecretRevision != 0) +
		",client_id=" + strconv.FormatBool(configuration.ClientID != "") +
		",redirect=" + strconv.FormatBool(configuration.RedirectURI != "") +
		",logout_redirect=" + strconv.FormatBool(configuration.PostLogoutRedirectURI != "") +
		",extra_scopes=" + strconv.Itoa(len(configuration.ExtraScopes)) +
		",refresh=" + strconv.FormatBool(configuration.AllowRefreshToken) +
		",userinfo=" + strconv.FormatBool(configuration.UseUserInfo) +
		"}"
}
func (configuration AuthorizationConfiguration) GoString() string { return configuration.String() }

func (start AuthorizationStart) String() string {
	return "federatedoidc.AuthorizationStart{" +
		"transaction=" + strconv.Quote(start.transactionID.String()) +
		",redirect=" + strconv.FormatBool(start.redirectURL != "") +
		",browser=" + strconv.FormatBool(len(start.browserHandle) != 0) +
		",valid=" + strconv.FormatBool(start.valid) +
		"}"
}
func (start AuthorizationStart) GoString() string { return start.String() }

func (request StartAuthorizationRequest) String() string {
	return "federatedoidc.StartAuthorizationRequest{" +
		"begin=" + strconv.Quote(request.Begin.String()) +
		",configuration=" + strconv.Quote(request.Configuration.String()) +
		",return_path=" + strconv.FormatBool(request.ReturnPath != "") +
		",previous_browser=" + strconv.FormatBool(len(request.PreviousBrowserHandle) != 0) +
		",application_browser=" + strconv.FormatBool(request.ApplicationBrowserBindingDigest != ([32]byte{})) +
		",audit=" + strconv.Quote(request.Audit.String()) +
		"}"
}
func (request StartAuthorizationRequest) GoString() string { return request.String() }

func (request callbackRequest) String() string {
	return "federatedoidc.callbackRequest{" +
		"configuration=" + strconv.Quote(request.Configuration.String()) +
		",query=" + strconv.FormatBool(request.RawQuery != "") +
		",browser=" + strconv.FormatBool(len(request.BrowserHandle) != 0) +
		"}"
}
func (request callbackRequest) GoString() string { return request.String() }

func (request ResolvedCallbackRequest) String() string {
	return "federatedoidc.ResolvedCallbackRequest{" +
		"query=" + strconv.FormatBool(request.RawQuery != "") +
		",browser=" + strconv.FormatBool(len(request.BrowserHandle) != 0) +
		",audit=" + strconv.Quote(request.Audit.String()) +
		"}"
}
func (request ResolvedCallbackRequest) GoString() string { return request.String() }

func (lookup CallbackConfigurationLookup) String() string {
	return "federatedoidc.CallbackConfigurationLookup{" +
		"transaction=" + strconv.Quote(lookup.TransactionID.String()) +
		",version=" + strconv.FormatBool(lookup.ExpectedVersion != 0) +
		",pins=" + strconv.Quote(lookup.Pins.String()) +
		",return_path=" + strconv.FormatBool(lookup.ReturnPath != "") +
		"}"
}
func (lookup CallbackConfigurationLookup) GoString() string { return lookup.String() }

func (claimed *ClaimedAuthorization) String() string {
	return "federatedoidc.ClaimedAuthorization{valid=" +
		strconv.FormatBool(claimed != nil) + "}"
}
func (claimed *ClaimedAuthorization) GoString() string { return claimed.String() }

func (rule ScalarClaimRule) String() string {
	return "federatedoidc.ScalarClaimRule{claim=" + strconv.FormatBool(rule.Claim != "") +
		",required=" + strconv.FormatBool(rule.Required) + "}"
}
func (rule ScalarClaimRule) GoString() string { return rule.String() }

func (rule ProfileClaimRule) String() string {
	return "federatedoidc.ProfileClaimRule{claim=" + strconv.FormatBool(rule.Claim != "") +
		",field=" + safeProfileField(rule.Field) +
		",required=" + strconv.FormatBool(rule.Required) + "}"
}
func (rule ProfileClaimRule) GoString() string { return rule.String() }

func (rule StringArrayClaimRule) String() string {
	return "federatedoidc.StringArrayClaimRule{claim=" + strconv.FormatBool(rule.Claim != "") +
		",required=" + strconv.FormatBool(rule.Required) + "}"
}
func (rule StringArrayClaimRule) GoString() string { return rule.String() }

func (policy ClaimExtractionPolicy) String() string {
	return "federatedoidc.ClaimExtractionPolicy{" +
		"scalars=" + strconv.Itoa(len(policy.Scalars)) +
		",profiles=" + strconv.Itoa(len(policy.Profiles)) +
		",groups=" + strconv.FormatBool(policy.Groups != nil) +
		",acr=" + strconv.FormatBool(policy.ACR != nil) +
		",amr=" + strconv.FormatBool(policy.AMR != nil) +
		"}"
}
func (policy ClaimExtractionPolicy) GoString() string { return policy.String() }

func (value NamedScalar) String() string {
	return "federatedoidc.NamedScalar{name=" + strconv.FormatBool(value.Name != "") +
		",value=" + strconv.FormatBool(value.Value != "") + "}"
}
func (value NamedScalar) GoString() string { return value.String() }

func (value ProfileValue) String() string {
	return "federatedoidc.ProfileValue{field=" + safeProfileField(value.Field) +
		",value=" + strconv.FormatBool(value.Value != "") + "}"
}
func (value ProfileValue) GoString() string { return value.String() }

func (claims ClaimSet) String() string {
	return "federatedoidc.ClaimSet{" +
		"scalars=" + strconv.Itoa(len(claims.scalars)) +
		",profiles=" + strconv.Itoa(len(claims.profiles)) +
		",groups=" + strconv.Itoa(len(claims.groups)) +
		",amr=" + strconv.Itoa(len(claims.amr)) +
		"}"
}
func (claims ClaimSet) GoString() string { return claims.String() }

func (proof VerifiedAuthentication) String() string {
	return "federatedoidc.VerifiedAuthentication{" +
		"valid=" + strconv.FormatBool(proof.valid) +
		",issuer=" + strconv.FormatBool(proof.issuer != "") +
		",subject=" + strconv.FormatBool(proof.subject != "") +
		",audience=" + strconv.Itoa(len(proof.audience)) +
		",claims=" + strconv.Quote(proof.claims.String()) +
		"}"
}
func (proof VerifiedAuthentication) GoString() string { return proof.String() }

func (bundle TokenBundle) String() string {
	access, refresh, destroyed := false, false, true
	if bundle.state != nil {
		bundle.state.mu.Lock()
		access = !bundle.state.destroyed && len(bundle.state.accessToken) != 0
		refresh = !bundle.state.destroyed && len(bundle.state.refreshToken) != 0
		destroyed = bundle.state.destroyed
		bundle.state.mu.Unlock()
	}
	return "federatedoidc.TokenBundle{access=" + strconv.FormatBool(access) +
		",refresh=" + strconv.FormatBool(refresh) +
		",destroyed=" + strconv.FormatBool(destroyed) + "}"
}
func (bundle TokenBundle) GoString() string { return bundle.String() }

func (request UserInfoRequest) String() string {
	return "federatedoidc.UserInfoRequest{endpoint=" + strconv.Quote(request.endpoint.String()) +
		",access_token=" + strconv.FormatBool(len(request.accessToken) != 0) +
		",valid=" + strconv.FormatBool(request.valid) + "}"
}
func (request UserInfoRequest) GoString() string { return request.String() }

func (request RevocationRequest) String() string {
	return "federatedoidc.RevocationRequest{endpoint=" + strconv.Quote(request.endpoint.String()) +
		",kind=" + safeTokenKind(request.tokenKind) +
		",token=" + strconv.FormatBool(len(request.token) != 0) +
		",client_authentication=" + safeClientAuthentication(request.clientAuthentication) +
		",client_id=" + strconv.FormatBool(request.clientID != "") +
		",client_secret=" + strconv.FormatBool(len(request.clientSecret) != 0) +
		",valid=" + strconv.FormatBool(request.valid) + "}"
}
func (request RevocationRequest) GoString() string { return request.String() }

func (request EndSessionRequest) String() string {
	return "federatedoidc.EndSessionRequest{endpoint=" + strconv.Quote(request.endpoint.String()) +
		",id_token=" + strconv.FormatBool(len(request.idTokenHint) != 0) +
		",redirect=" + strconv.FormatBool(request.postLogoutRedirectURI != "") +
		",state=" + strconv.FormatBool(len(request.state) != 0) +
		",valid=" + strconv.FormatBool(request.valid) + "}"
}
func (request EndSessionRequest) GoString() string { return request.String() }

func safeTransactionState(state TransactionState) string {
	switch state {
	case TransactionPending, TransactionClaimed, TransactionCompleted, TransactionFailed, TransactionExpired:
		return string(state)
	default:
		return "unknown"
	}
}

func safeFailureReason(reason TransactionFailureReason) string {
	if validFailureReason(reason) {
		return string(reason)
	}
	return "unknown"
}

func safeCeremonyAuthority(authority CeremonyAuthority) string {
	switch authority {
	case TenantCeremonyAuthority:
		return "tenant"
	case DirectPlatformCeremonyAuthority:
		return "direct_platform"
	default:
		return "unknown"
	}
}

func safeCallbackEndpoint(endpoint CallbackEndpoint) string {
	switch endpoint {
	case TenantOIDCCallbackEndpoint:
		return "tenant"
	case DirectPlatformOIDCCallbackEndpoint:
		return "direct_platform"
	default:
		return "unknown"
	}
}

func safeEndpointKind(kind EndpointKind) string {
	switch kind {
	case EndpointToken, EndpointUserInfo, EndpointRevocation, EndpointEndSession:
		return string(kind)
	default:
		return "unknown"
	}
}

func safeTokenEndpointCategory(category TokenEndpointCategory) string {
	switch category {
	case TokenEndpointSuccess, TokenEndpointRejected, TokenEndpointUnavailable,
		TokenEndpointLimited, TokenEndpointCancelled:
		return string(category)
	default:
		return "unknown"
	}
}

func safeTokenKind(kind TokenKind) string {
	switch kind {
	case TokenAccess, TokenRefresh:
		return string(kind)
	default:
		return "unknown"
	}
}

func safeProfileField(field ProfileField) string {
	if validProfileField(field) {
		return string(field)
	}
	return "unknown"
}

func positive(value int) string { return strconv.FormatBool(value > 0) }

func positiveDuration(value time.Duration) string {
	return strconv.FormatBool(value.Nanoseconds() > 0)
}
