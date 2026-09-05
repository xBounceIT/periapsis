package federatedsaml

import (
	"strconv"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func (value SignaturePolicy) String() string {
	if validSignaturePolicy(value) {
		return string(value)
	}
	return "unknown"
}
func (value SignaturePolicy) GoString() string { return value.String() }

func (value EncryptionPolicy) String() string {
	switch value {
	case EncryptionDisabled, EncryptionOptional, EncryptionRequired:
		return string(value)
	default:
		return "unknown"
	}
}
func (value EncryptionPolicy) GoString() string { return value.String() }

func (value SubjectSource) String() string {
	if value == SubjectPersistentNameID || value == SubjectImmutableAttribute {
		return string(value)
	}
	return "unknown"
}
func (value SubjectSource) GoString() string { return value.String() }

func (value RedirectSignatureAlgorithm) String() string {
	if validRedirectAlgorithm(value) {
		return string(value)
	}
	return "unknown"
}
func (value RedirectSignatureAlgorithm) GoString() string { return value.String() }

func (value CeremonyAuthority) String() string   { return safeCeremonyAuthority(value) }
func (value CeremonyAuthority) GoString() string { return value.String() }

func (value ScalarAttributeRule) String() string {
	return "federatedsaml.ScalarAttributeRule{" +
		"name_present=" + strconv.FormatBool(value.Name != "") +
		",format_present=" + strconv.FormatBool(value.NameFormat != "") +
		",required=" + strconv.FormatBool(value.Required) +
		"}"
}
func (value ScalarAttributeRule) GoString() string { return value.String() }

func (value ProfileAttributeRule) String() string {
	return "federatedsaml.ProfileAttributeRule{" +
		"name_present=" + strconv.FormatBool(value.Name != "") +
		",format_present=" + strconv.FormatBool(value.NameFormat != "") +
		",field=" + safeProfileField(value.Field) +
		",required=" + strconv.FormatBool(value.Required) +
		"}"
}
func (value ProfileAttributeRule) GoString() string { return value.String() }

func (value GroupAttributeRule) String() string {
	return "federatedsaml.GroupAttributeRule{" +
		"name_present=" + strconv.FormatBool(value.Name != "") +
		",format_present=" + strconv.FormatBool(value.NameFormat != "") +
		",required=" + strconv.FormatBool(value.Required) +
		"}"
}
func (value GroupAttributeRule) GoString() string { return value.String() }

func (value SubjectPolicy) String() string {
	return "federatedsaml.SubjectPolicy{" +
		"source=" + value.Source.String() +
		",attribute_name_present=" + strconv.FormatBool(value.AttributeName != "") +
		",attribute_format_present=" + strconv.FormatBool(value.AttributeNameFormat != "") +
		"}"
}
func (value SubjectPolicy) GoString() string { return value.String() }

func (value AttributeMappingPolicy) String() string {
	return "federatedsaml.AttributeMappingPolicy{" +
		"scalars=" + strconv.Itoa(len(value.Scalars)) +
		",profiles=" + strconv.Itoa(len(value.Profiles)) +
		",groups=" + strconv.FormatBool(value.Groups != nil) +
		"}"
}
func (value AttributeMappingPolicy) GoString() string { return value.String() }

func (value AuthnContextTrustRule) String() string {
	return "federatedsaml.AuthnContextTrustRule{" +
		"class_ref_present=" + strconv.FormatBool(value.ClassRef != "") +
		",revision=" + strconv.FormatBool(value.Revision > 0) +
		",max_age_present=" + strconv.FormatBool(value.MaxAge > 0) +
		"}"
}
func (value AuthnContextTrustRule) GoString() string { return value.String() }

func (value Limits) String() string {
	return "federatedsaml.Limits{" +
		"valid=" + strconv.FormatBool(validLimits(value)) +
		",xml_bounded=" + strconv.FormatBool(value.MaxXMLDepth > 0 && value.MaxXMLNodes > 0 && value.MaxXMLAttributes > 0) +
		",certificates=" + strconv.Itoa(value.MaxCertificates) +
		",attributes=" + strconv.Itoa(value.MaxAttributes) +
		"}"
}
func (value Limits) GoString() string { return value.String() }

func (value Options) String() string {
	return "federatedsaml.Options{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",transactions=" + strconv.FormatBool(value.Transactions != nil) +
		",redirect_signer=" + strconv.FormatBool(value.RedirectSigner != nil) +
		",signature_verifier=" + strconv.FormatBool(value.SignatureVerifier != nil) +
		",assertion_decrypter=" + strconv.FormatBool(value.AssertionDecrypter != nil) +
		",session_protector=" + strconv.FormatBool(value.SessionProtector != nil) +
		",limits=" + strconv.Quote(value.Limits.String()) +
		"}"
}
func (value Options) GoString() string { return value.String() }

func (kernel *Kernel) String() string {
	return "federatedsaml.Kernel{" +
		"authority=" + safeKernelAuthority(kernel) +
		",configured=" + strconv.FormatBool(kernel != nil && kernel.transactions != nil && kernel.redirectSigner != nil && kernel.signatureVerifier != nil && kernel.assertionDecrypter != nil && kernel.sessionProtector != nil) +
		"}"
}
func (kernel *Kernel) GoString() string { return kernel.String() }

func (value MetadataSnapshot) String() string {
	return "federatedsaml.MetadataSnapshot{" +
		"valid=" + strconv.FormatBool(value.valid) +
		",revision=" + strconv.FormatBool(value.revision > 0) +
		",digest=" + strconv.FormatBool(value.digest != [32]byte{}) +
		",entity_id_present=" + strconv.FormatBool(value.entityID != "") +
		",sso_endpoint_present=" + strconv.FormatBool(value.ssoRedirectURL != "") +
		",slo_endpoint_present=" + strconv.FormatBool(value.sloRedirectURL != "") +
		",certificates=" + strconv.Itoa(len(value.certificateSummaries)) +
		"}"
}
func (value MetadataSnapshot) GoString() string { return value.String() }

func (value MetadataCompilationRequest) String() string {
	return "federatedsaml.MetadataCompilationRequest{" +
		"document_bytes=" + strconv.Itoa(len(value.Document)) +
		",entity_id_present=" + strconv.FormatBool(value.ExpectedEntityID != "") +
		",revision=" + strconv.FormatBool(value.Revision > 0) +
		"}"
}
func (value MetadataCompilationRequest) GoString() string { return value.String() }

func (value MetadataLoadRequest) String() string {
	return "federatedsaml.MetadataLoadRequest{" +
		"provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",entity_id_present=" + strconv.FormatBool(value.ExpectedEntityID != "") +
		",revision=" + strconv.FormatBool(value.Revision > 0) +
		"}"
}
func (value MetadataLoadRequest) GoString() string { return value.String() }

func (value MetadataDocument) String() string {
	return "federatedsaml.MetadataDocument{" +
		"document_bytes=" + strconv.Itoa(len(value.Document)) +
		",retrieved_at_present=" + strconv.FormatBool(!value.RetrievedAt.IsZero()) +
		"}"
}
func (value MetadataDocument) GoString() string { return value.String() }

func (value Configuration) String() string {
	return "federatedsaml.Configuration{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		",plan_revision=" + strconv.FormatBool(value.PlanRevision != 0) +
		",metadata=" + strconv.Quote(value.Metadata.String()) +
		",signature_policy=" + value.SignaturePolicy.String() +
		",encryption_policy=" + value.EncryptionPolicy.String() +
		",subject_source=" + value.Subject.Source.String() +
		",requested_contexts=" + strconv.Itoa(len(value.RequestedAuthnContexts)) +
		",trust_rules=" + strconv.Itoa(len(value.TrustRules)) +
		"}"
}
func (value Configuration) GoString() string { return value.String() }

func (value TransactionPins) String() string {
	return "federatedsaml.TransactionPins{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",provider_revision=" + strconv.FormatBool(value.ProviderRevision > 0) +
		",binding_revision=" + strconv.FormatBool(value.BindingRevision > 0) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision > 0) +
		",configuration_revision=" + strconv.FormatBool(value.ConfigurationRevision > 0) +
		",security_revision=" + strconv.FormatBool(value.SecurityRevision > 0) +
		",plan_revision=" + strconv.FormatBool(value.PlanRevision > 0) +
		",mapping_revision=" + strconv.FormatBool(value.MappingRevision > 0) +
		",authorization_revision=" + strconv.FormatBool(value.AuthorizationRevision > 0) +
		",assurance_revision=" + strconv.FormatBool(value.AssurancePolicyRevision > 0) +
		",metadata_revision=" + strconv.FormatBool(value.MetadataRevision > 0) +
		",metadata_digest=" + strconv.FormatBool(value.MetadataDigest != [32]byte{}) +
		",sp_key_revision=" + strconv.FormatBool(value.SPKeyRevision > 0) +
		",configuration_digest=" + strconv.FormatBool(value.ConfigurationDigest != [32]byte{}) +
		"}"
}
func (value TransactionPins) GoString() string { return value.String() }

func (value TransactionID) String() string {
	return "federatedsaml.TransactionID{valid=" + strconv.FormatBool(!allZero(value[:])) + "}"
}
func (value TransactionID) GoString() string { return value.String() }

func (value AuthenticationBegin) String() string {
	return "federatedsaml.AuthenticationBegin{" +
		"operation_present=" + strconv.FormatBool(value.OperationRunID != (identity.EntityID{})) +
		",digests_present=" + strconv.FormatBool(validAuthenticationBegin(value)) +
		"}"
}
func (value AuthenticationBegin) GoString() string { return value.String() }

func (value PendingTransaction) String() string {
	return "federatedsaml.PendingTransaction{" +
		"authority=" + safeCeremonyAuthority(value.Pins.Authority) +
		",id=" + strconv.Quote(value.ID.String()) +
		",material_present=" + strconv.FormatBool(validUUIDv7(value.MaterialID)) +
		",request_id_present=" + strconv.FormatBool(value.RequestID != "") +
		",return_path_present=" + strconv.FormatBool(value.ReturnPath != "") +
		",state=" + safeTransactionState(value.State) +
		",version=" + strconv.FormatBool(value.Version > 0) +
		"}"
}
func (value PendingTransaction) GoString() string { return value.String() }

func (value CreateTransactionRequest) String() string {
	return "federatedsaml.CreateTransactionRequest{" +
		"begin=" + strconv.Quote(value.Begin.String()) +
		",current=" + strconv.Quote(value.Current.String()) +
		",previous_browser_binding=" + strconv.FormatBool(value.HasPreviousBrowserBinding) +
		"}"
}
func (value CreateTransactionRequest) GoString() string { return value.String() }

func (value RedirectSignRequest) String() string {
	return "federatedsaml.RedirectSignRequest{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		",key_revision=" + strconv.FormatBool(value.KeyRevision > 0) +
		",logout_material=" + strconv.FormatBool(validEntityID(value.LogoutMaterialID)) +
		",algorithm=" + value.Algorithm.String() +
		",payload_bytes=" + strconv.Itoa(len(value.Payload)) +
		"}"
}
func (value RedirectSignRequest) GoString() string { return value.String() }

func (value SignatureVerificationRequest) String() string {
	return "federatedsaml.SignatureVerificationRequest{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		",document_bytes=" + strconv.Itoa(len(value.Document)) +
		",object_kind=" + safeSignedObject(value.ObjectKind) +
		",object_id_present=" + strconv.FormatBool(value.ObjectID != "") +
		",metadata=" + strconv.Quote(value.Metadata.String()) +
		"}"
}
func (value SignatureVerificationRequest) GoString() string { return value.String() }

func (value SignatureVerificationResult) String() string {
	return "federatedsaml.SignatureVerificationResult{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		",object_kind=" + safeSignedObject(value.ObjectKind) +
		",object_id_present=" + strconv.FormatBool(value.ObjectID != "") +
		",reference_present=" + strconv.FormatBool(value.ReferenceURI != "") +
		",signature_algorithm_present=" + strconv.FormatBool(value.SignatureAlgorithm != "") +
		",digest_algorithm_present=" + strconv.FormatBool(value.DigestAlgorithm != "") +
		",references=" + strconv.Itoa(value.ReferenceCount) +
		",key_info_certificates=" + strconv.Itoa(value.KeyInfoCertificateCount) +
		",matching_certificates=" + strconv.Itoa(value.MatchingCertificateCount) +
		",external_dereferences=" + strconv.Itoa(value.ExternalDereferenceCount) +
		"}"
}
func (value SignatureVerificationResult) GoString() string { return value.String() }

func (value DecryptionRequest) String() string {
	return "federatedsaml.DecryptionRequest{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",response_bytes=" + strconv.Itoa(len(value.Response)) +
		",response_id_present=" + strconv.FormatBool(value.ResponseID != "") +
		",encrypted_object_id_present=" + strconv.FormatBool(value.EncryptedObjectID != "") +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		",key_versions=" + strconv.Itoa(len(value.AllowedKeyVersions)) +
		",direct_key_revisions=" + strconv.Itoa(len(value.DirectPlatformKeyRevisions)) +
		"}"
}
func (value DecryptionRequest) GoString() string { return value.String() }

func (value DecryptionResult) String() string {
	return "federatedsaml.DecryptionResult{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		",assertion_bytes=" + strconv.Itoa(len(value.Assertion)) +
		",key_version=" + strconv.FormatBool(value.KeyVersion > 0) +
		",direct_key_revision=" + strconv.FormatBool(value.DirectPlatformKeyRevision > 0) +
		",encrypted_object_id_present=" + strconv.FormatBool(value.EncryptedObjectID != "") +
		",algorithms_present=" + strconv.FormatBool(value.ContentEncryptionAlgorithm != "" && value.KeyTransportAlgorithm != "") +
		",external_dereferences=" + strconv.Itoa(value.ExternalDereferenceCount) +
		"}"
}
func (value DecryptionResult) GoString() string { return value.String() }

func (value ProtectedSessionMaterial) String() string {
	return "federatedsaml.ProtectedSessionMaterial{" +
		"key_version=" + strconv.FormatBool(value.KeyVersion > 0) +
		",ciphertext_bytes=" + strconv.Itoa(len(value.Ciphertext)) +
		"}"
}
func (value ProtectedSessionMaterial) GoString() string { return value.String() }

func (value SessionMaterial) String() string {
	return "federatedsaml.SessionMaterial{" +
		"name_id_present=" + strconv.FormatBool(value.NameID != "") +
		",name_id_format_present=" + strconv.FormatBool(value.NameIDFormat != "") +
		",session_index_present=" + strconv.FormatBool(value.SessionIndex != "") +
		"}"
}
func (value SessionMaterial) GoString() string { return value.String() }

func (value SessionMaterialContext) String() string {
	return "federatedsaml.SessionMaterialContext{" +
		"authority=" + safeCeremonyAuthority(value.Authority) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.BindingID)) +
		",material_present=" + strconv.FormatBool(validEntityID(value.MaterialID)) +
		",platform_login=" + strconv.FormatBool(value.PlatformLoginRevision != 0) +
		"}"
}
func (value SessionMaterialContext) GoString() string { return value.String() }

func (value AuthorizationStart) String() string {
	return "federatedsaml.AuthorizationStart{" +
		"valid=" + strconv.FormatBool(value.valid) +
		",transaction_id=" + strconv.Quote(value.transactionID.String()) +
		",redirect_present=" + strconv.FormatBool(value.redirectURL != "") +
		",browser_handle_present=" + strconv.FormatBool(len(value.browserHandle) > 0) +
		"}"
}
func (value AuthorizationStart) GoString() string { return value.String() }

func (value StartRequest) String() string {
	return "federatedsaml.StartRequest{" +
		"begin=" + strconv.Quote(value.Begin.String()) +
		",configuration=" + strconv.Quote(value.Configuration.String()) +
		",return_path_present=" + strconv.FormatBool(value.ReturnPath != "") +
		",previous_browser_handle_present=" + strconv.FormatBool(len(value.PreviousBrowserHandle) > 0) +
		",live_session=" + strconv.FormatBool(value.HasLiveSession) +
		"}"
}
func (value StartRequest) GoString() string { return value.String() }

func (value CallbackRequest) String() string {
	return "federatedsaml.CallbackRequest{" +
		"configuration=" + strconv.Quote(value.Configuration.String()) +
		",media_type_present=" + strconv.FormatBool(value.MediaType != "") +
		",form_bytes=" + strconv.Itoa(len(value.RawForm)) +
		",browser_handle_present=" + strconv.FormatBool(len(value.BrowserHandle) > 0) +
		"}"
}
func (value CallbackRequest) GoString() string { return value.String() }

func (value NamedScalar) String() string {
	return "federatedsaml.NamedScalar{name_present=" + strconv.FormatBool(value.Name != "") + ",value_present=" + strconv.FormatBool(value.Value != "") + "}"
}
func (value NamedScalar) GoString() string { return value.String() }

func (value ProfileValue) String() string {
	return "federatedsaml.ProfileValue{field=" + safeProfileField(value.Field) + ",value_present=" + strconv.FormatBool(value.Value != "") + "}"
}
func (value ProfileValue) GoString() string { return value.String() }

func (value JITAuthentication) String() string {
	return "federatedsaml.JITAuthentication{" +
		"issuer_present=" + strconv.FormatBool(value.issuer != "") +
		",subject_source=" + value.subjectSource.String() +
		",subject_present=" + strconv.FormatBool(value.subjectValue != "") +
		",scalars=" + strconv.Itoa(len(value.scalars)) +
		",profiles=" + strconv.Itoa(len(value.profiles)) +
		",groups=" + strconv.Itoa(len(value.groups)) +
		",authn_context_present=" + strconv.FormatBool(value.authnContext != "") +
		",valid_until_present=" + strconv.FormatBool(!value.validUntil.IsZero()) +
		",assurance_present=" + strconv.FormatBool(value.assurance != nil) +
		",session_material=" + strconv.Quote(value.protectedSession.String()) +
		"}"
}
func (value JITAuthentication) GoString() string { return value.String() }

func (value ConsumptionRequest) String() string {
	return "federatedsaml.ConsumptionRequest{" +
		"authority=" + safeCeremonyAuthority(value.Pins.Authority) +
		",platform_login=" + strconv.FormatBool(value.Pins.PlatformLoginRevision != 0) +
		",transaction_id=" + strconv.Quote(value.TransactionID.String()) +
		",material_present=" + strconv.FormatBool(validUUIDv7(value.MaterialID)) +
		",version=" + strconv.FormatBool(value.ExpectedVersion > 0) +
		",response_id_present=" + strconv.FormatBool(value.ResponseID != "") +
		",assertion_id_present=" + strconv.FormatBool(value.AssertionID != "") +
		",session_replay_present=" + strconv.FormatBool(value.HasSessionIndex) +
		",return_path_present=" + strconv.FormatBool(value.ReturnPath != "") +
		",authentication=" + strconv.Quote(value.Authentication.String()) +
		"}"
}
func (value ConsumptionRequest) GoString() string { return value.String() }

func (value *ValidatedAuthentication) String() string {
	return "federatedsaml.ValidatedAuthentication{" +
		"present=" + strconv.FormatBool(value != nil) +
		",ready=" + strconv.FormatBool(value != nil && value.stage.Load() == validatedReady) +
		"}"
}
func (value *ValidatedAuthentication) GoString() string { return value.String() }

func (value LogoutRequest) String() string {
	return "federatedsaml.LogoutRequest{" +
		"valid=" + strconv.FormatBool(value.valid) +
		",redirect_present=" + strconv.FormatBool(value.redirectURL != "") +
		",request_id_present=" + strconv.FormatBool(value.requestID != "") +
		"}"
}
func (value LogoutRequest) GoString() string { return value.String() }

func (value LogoutBuildRequest) String() string {
	return "federatedsaml.LogoutBuildRequest{" +
		"configuration=" + strconv.Quote(value.Configuration.String()) +
		",session_present=" + strconv.FormatBool(validEntityID(value.SessionID)) +
		",material_present=" + strconv.FormatBool(validEntityID(value.MaterialID)) +
		",protected_material=" + strconv.Quote(value.ProtectedMaterial.String()) +
		",confirmation_present=" + strconv.FormatBool(value.Confirmation != nil) +
		"}"
}
func (value LogoutBuildRequest) GoString() string { return value.String() }

func (value StoredLogoutConfiguration) String() string {
	return "federatedsaml.StoredLogoutConfiguration{" +
		"authority=" + strconv.Quote(value.Authority.String()) +
		",provider_present=" + strconv.FormatBool(validProvider(value.Provider)) +
		",binding_present=" + strconv.FormatBool(validEntityID(value.MaterialBindingID)) +
		",platform_login_revision=" + strconv.FormatUint(value.PlatformLoginRevision, 10) +
		",sp_entity_present=" + strconv.FormatBool(value.SPEntityID != "") +
		",slo_redirect_present=" + strconv.FormatBool(value.SLORedirectURL != "") +
		",sp_key_revision=" + strconv.FormatUint(value.SPKeyRevision, 10) +
		",redirect_signature_algorithm=" + strconv.Quote(value.RedirectSignatureAlgorithm.String()) +
		"}"
}
func (value StoredLogoutConfiguration) GoString() string { return value.String() }

func (value StoredLogoutBuildRequest) String() string {
	return "federatedsaml.StoredLogoutBuildRequest{" +
		"configuration=" + strconv.Quote(value.Configuration.String()) +
		",session_present=" + strconv.FormatBool(validEntityID(value.SessionID)) +
		",material_present=" + strconv.FormatBool(validEntityID(value.MaterialID)) +
		",protected_material=" + strconv.Quote(value.ProtectedMaterial.String()) +
		",confirmation_present=" + strconv.FormatBool(value.Confirmation != nil) +
		"}"
}
func (value StoredLogoutBuildRequest) GoString() string { return value.String() }

func safeTransactionState(value TransactionState) string {
	switch value {
	case TransactionPending, TransactionCompleted, TransactionExpired, TransactionFailed:
		return string(value)
	default:
		return "unknown"
	}
}

func safeSignedObject(value SignedObjectKind) string {
	if value == SignedObjectResponse || value == SignedObjectAssertion {
		return string(value)
	}
	return "unknown"
}

func safeCeremonyAuthority(value CeremonyAuthority) string {
	switch value {
	case TenantCeremonyAuthority:
		return "tenant"
	case DirectPlatformCeremonyAuthority:
		return "direct_platform"
	default:
		return "unknown"
	}
}

func safeKernelAuthority(kernel *Kernel) string {
	if kernel == nil {
		return "unknown"
	}
	return safeCeremonyAuthority(kernel.authority)
}

func safeProfileField(value ProfileField) string {
	if validProfileField(value) {
		return string(value)
	}
	return "unknown"
}
