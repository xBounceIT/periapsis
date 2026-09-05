package platformldapauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"golang.org/x/text/cases"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	minimumOperationTimeout = time.Second
	maximumOperationTimeout = 5 * time.Minute
	maximumSelectedMappings = 128
	platformSuperAdminKey   = "platform_super_admin"
)

type Options struct {
	Repository       Repository
	Directory        DirectoryClient
	Keyring          identity.Keyring
	TOTPVerifier     platformoidcauth.DirectTOTPVerifier
	Credentials      federatedauth.ApplyCredentialIssuer
	RateDigestKey    []byte
	OperationTimeout time.Duration
	Now              func() time.Time
	NewID            func() (uuid.UUID, error)
	Random           io.Reader
}

type Service struct {
	repository       Repository
	directory        DirectoryClient
	keyring          identity.Keyring
	totpVerifier     platformoidcauth.DirectTOTPVerifier
	credentials      federatedauth.ApplyCredentialIssuer
	rateDigestKey    [sha256.Size]byte
	operationTimeout time.Duration
	now              func() time.Time
	newID            func() (uuid.UUID, error)
	random           io.Reader
}

func New(options Options) (*Service, error) {
	if options.Repository == nil || options.Directory == nil || options.TOTPVerifier == nil ||
		options.Credentials == nil || len(options.Keyring.Versions()) == 0 ||
		len(options.RateDigestKey) != sha256.Size ||
		options.OperationTimeout < minimumOperationTimeout ||
		options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidInput
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewID == nil {
		options.NewID = uuid.NewV7
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	service := &Service{
		repository: options.Repository, directory: options.Directory,
		keyring: options.Keyring, totpVerifier: options.TOTPVerifier,
		credentials: options.Credentials, operationTimeout: options.OperationTimeout,
		now: options.Now, newID: options.NewID, random: options.Random,
	}
	copy(service.rateDigestKey[:], options.RateDigestKey)
	return service, nil
}

// Authenticate takes ownership of Password and TOTPCode and clears both
// backing arrays on every return path. It never creates a user and never
// produces a post-primary continuation.
func (service *Service) Authenticate(ctx context.Context, command Command) (Result, error) {
	defer clear(command.Password)
	defer clear(command.TOTPCode)
	if service == nil || ctx == nil || ctx.Err() != nil || !validCommand(command) {
		return Result{}, ErrInvalidInput
	}
	operation, cancel := context.WithTimeout(ctx, service.operationTimeout)
	defer cancel()
	ids, err := service.ids(5)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	receipt := make([]byte, sha256.Size)
	if _, err = io.ReadFull(service.random, receipt); err != nil || allZero(receipt) {
		clear(receipt)
		return Result{}, ErrUnavailable
	}
	receiptDigest := sha256.Sum256(receipt)
	clear(receipt)
	rateDigests := service.rateDigests(command)
	snapshot, err := service.repository.Begin(operation, BeginRequest{
		RunID: ids[0], ReceiptDigest: receiptDigest, ProviderKey: command.ProviderKey,
		NetworkRateDigest: rateDigests[0], AccountRateDigest: rateDigests[1],
		ProviderRateDigest: rateDigests[2], Audit: service.audit(command, ids[2]),
	})
	if err != nil {
		return Result{}, mapBeginError(err)
	}
	defer snapshot.Destroy()
	needsFailure := true
	failureCategory := FailureProtocolFailed
	defer func() {
		if needsFailure {
			service.finalizeFailure(ctx, ids[0], command, ids[3], failureCategory)
		}
	}()
	if !validNetworkSnapshot(snapshot, ids[0]) {
		return Result{}, ErrAuthentication
	}
	if !snapshot.Allowed || snapshot.State != RunPending {
		needsFailure = false
		if snapshot.FailureCategory == FailureRateLimited {
			return Result{}, ErrRateLimited
		}
		return Result{}, ErrAuthentication
	}
	normalizedConfiguration, normalizedEndpoints, err := identityprovider.NormalizeLDAPConfiguration(
		snapshot.Configuration, snapshot.Endpoints,
	)
	if err != nil || normalizedConfiguration.JITMode != identityprovider.JITModeExistingIdentity ||
		normalizedConfiguration.NoMatchPolicy != identityprovider.NoMatchPolicyDeny {
		failureCategory = FailureStaleConfiguration
		return Result{}, ErrUnavailable
	}
	snapshot.Configuration = normalizedConfiguration
	snapshot.Endpoints = normalizedEndpoints

	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(snapshot.ProviderID),
	}
	bindSecret, err := service.keyring.DecryptBindSecret(identity.BindSecretContext{
		Provider: provider, SecretID: identity.EntityID(snapshot.BindSecretID),
	}, snapshot.BindSecret)
	if err != nil {
		failureCategory = FailureProviderUnavailable
		return Result{}, ErrUnavailable
	}
	directoryRequest, err := identityprovider.BuildDirectoryAuthenticationRequest(
		snapshot.Configuration, snapshot.Endpoints, command.Username,
	)
	if err != nil {
		clear(bindSecret)
		failureCategory = FailureProtocolFailed
		return Result{}, ErrUnavailable
	}
	defer identityprovider.ClearDirectoryAuthenticationRequest(&directoryRequest)
	directoryResult, directoryErr := service.directory.AuthenticateDirectory(
		operation, directoryRequest, bindSecret, command.Password,
	)
	// The adapter owns these slices. Re-clear them for faulty adapters and test
	// doubles, and never retain a credential after the network boundary.
	clear(bindSecret)
	clear(command.Password)
	if directoryErr != nil || directoryResult.Category != ldapclient.DirectoryCategorySuccess {
		category, publicErr := mapDirectoryFailure(directoryResult.Category, directoryErr)
		failureCategory = category
		return Result{}, publicErr
	}
	if operation.Err() != nil {
		failureCategory = FailureProviderUnavailable
		return Result{}, ErrUnavailable
	}

	normalization, err := identityprovider.BuildDirectoryNormalizationConfiguration(
		snapshot.Configuration, command.Username,
	)
	if err != nil {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrUnavailable
	}
	observation, err := ldapclient.NormalizeDirectoryObservation(normalization, directoryResult.Observation)
	if err != nil || !observation.Complete() {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrUnavailable
	}
	if observation.AccountState() != identity.LDAPAccountActive {
		failureCategory = FailureAccountDisabled
		return Result{}, ErrAuthentication
	}
	profile, err := observationProfile(observation)
	if err != nil {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrAuthentication
	}
	groups, err := canonicalGroups(directoryResult.Observation.Groups)
	if err != nil || len(groups) != observation.GroupCount() {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrAuthentication
	}

	aliases, err := observation.SubjectAliases(service.keyring, provider)
	if err != nil {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrUnavailable
	}
	defer clearAliases(aliases)
	activeAlias, ok := activeSubjectAlias(aliases, service.keyring.ActiveVersion())
	if !ok {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrUnavailable
	}
	mfaSnapshot, err := service.repository.LoadMFA(operation, LoadMFARequest{
		RunID: snapshot.RunID, ProviderID: snapshot.ProviderID,
		ProviderVersion:       snapshot.ProviderVersion,
		ConfigurationRevision: snapshot.ConfigurationRevision,
		SecurityRevision:      snapshot.SecurityRevision, MappingRevision: snapshot.MappingRevision,
		ExternalIdentityID: ids[1], SubjectDigest: activeAlias.Digest,
		SubjectKeyVersion: activeAlias.KeyVersion, Email: cloneString(profile.Email),
	})
	if err != nil {
		failureCategory = classifyLoadError(err)
		return Result{}, mapAuthenticationError(err)
	}
	defer mfaSnapshot.Destroy()
	if !validMFASnapshot(mfaSnapshot, snapshot) {
		category := FailureIdentityUnmatched
		if validUUIDv7(mfaSnapshot.UserID) && mfaSnapshot.TOTP.ID == uuid.Nil {
			category = FailureMFARequired
		}
		failureCategory = category
		return Result{}, ErrAuthentication
	}
	selected, err := selectMappings(groups, mfaSnapshot.Mappings)
	if err != nil || len(selected) == 0 {
		failureCategory = FailureMappingUnmatched
		return Result{}, ErrAuthentication
	}
	if len(command.TOTPCode) == 0 {
		failureCategory = FailureMFARequired
		return Result{}, ErrAuthentication
	}
	if !validTOTPCode(command.TOTPCode) {
		failureCategory = FailureMFARejected
		return Result{}, ErrAuthentication
	}
	completedAt := service.currentTime()
	verification := platformoidcauth.DirectTOTPVerificationRequest{
		UserID: identity.EntityID(mfaSnapshot.UserID), FactorID: identity.EntityID(mfaSnapshot.TOTP.ID),
		FactorRevision: mfaSnapshot.TOTP.SecurityRevision,
		Secret:         cloneTOTPSecret(mfaSnapshot.TOTP.Secret), Code: append([]byte(nil), command.TOTPCode...),
		At: completedAt, LastAcceptedCounter: cloneCounter(mfaSnapshot.TOTP.LastAcceptedCounter),
	}
	proof, verifyErr := service.totpVerifier.VerifyDirectTOTP(operation, verification)
	verification.Secret.Destroy()
	clear(verification.Code)
	if verification.LastAcceptedCounter != nil {
		*verification.LastAcceptedCounter = 0
	}
	clear(command.TOTPCode)
	if verifyErr != nil || proof.Counter < 0 ||
		mfaSnapshot.TOTP.LastAcceptedCounter != nil && proof.Counter <= *mfaSnapshot.TOTP.LastAcceptedCounter {
		if errors.Is(verifyErr, platformoidcauth.ErrDirectTOTPInvalidProof) || verifyErr == nil {
			failureCategory = FailureMFARejected
			return Result{}, ErrAuthentication
		}
		failureCategory = FailureProviderUnavailable
		return Result{}, ErrUnavailable
	}

	envelope, protectedAliases, err := observation.ProtectSubject(service.keyring, identity.ExternalSubjectContext{
		Provider: provider, ExternalIdentityID: identity.EntityID(mfaSnapshot.ExternalIdentityID),
	})
	if err != nil {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrUnavailable
	}
	defer clear(envelope.Ciphertext)
	defer clearAliases(protectedAliases)
	protectedAlias, ok := activeSubjectAlias(protectedAliases, service.keyring.ActiveVersion())
	if !ok || protectedAlias != activeAlias {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrAuthentication
	}
	reservation, err := service.credentials.ReserveApplyCredential(federatedauth.ApplyCredentialRequest{
		Disposition: federatedauth.ApplySession, Method: federatedauth.AuthenticationMethodLDAP,
		IssuedAt: completedAt,
	})
	if err != nil || reservation == nil || !validSessionReservation(reservation, completedAt) {
		if reservation != nil {
			reservation.Destroy()
		}
		failureCategory = FailureProviderUnavailable
		return Result{}, ErrUnavailable
	}
	defer reservation.Destroy()
	selectedIDs := make([]uuid.UUID, len(selected))
	for index := range selected {
		selectedIDs[index] = selected[index].ID
	}
	groupsDigest := digestGroups(groups)
	resultDigest, ok := applyDigest(snapshot, mfaSnapshot, envelope, protectedAlias, profile,
		groupsDigest, selectedIDs, proof.Counter, reservation.Session(), completedAt, command.ReturnPath)
	if !ok {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrAuthentication
	}
	apply := ApplyRequest{
		RunID: snapshot.RunID, ProviderID: snapshot.ProviderID, ProviderVersion: snapshot.ProviderVersion,
		ConfigurationRevision: snapshot.ConfigurationRevision,
		SecurityRevision:      snapshot.SecurityRevision, MappingRevision: snapshot.MappingRevision,
		UserID: mfaSnapshot.UserID, UserAuthenticationRevision: mfaSnapshot.UserAuthenticationRevision,
		ExternalIdentityID: mfaSnapshot.ExternalIdentityID, IdentityVersion: mfaSnapshot.IdentityVersion,
		SubjectEnvelope: envelope, SubjectAlias: protectedAlias, Profile: profile,
		GroupsDigest: groupsDigest, SelectedMappingIDs: selectedIDs,
		TOTPFactorID: mfaSnapshot.TOTP.ID, TOTPSecurityRevision: mfaSnapshot.TOTP.SecurityRevision,
		TOTPCounter: proof.Counter, Session: reservation, CompletedAt: completedAt,
		ResultDigest: resultDigest, Audit: service.audit(command, ids[4]),
	}
	applied, err := service.repository.Apply(operation, apply)
	if err != nil {
		if errors.Is(err, ErrStaleConfiguration) || errors.Is(err, ErrReplayConflict) {
			failureCategory = FailureStaleConfiguration
			return Result{}, ErrAuthentication
		}
		failureCategory = FailureProviderUnavailable
		return Result{}, ErrUnavailable
	}
	if !validApplyResult(applied, apply) {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrAuthentication
	}
	browserCredential, released := reservation.ReleaseBrowserCredential(applied.SessionID, identity.EntityID{})
	if !released || browserCredential == nil {
		failureCategory = FailureProtocolFailed
		return Result{}, ErrAuthentication
	}
	needsFailure = false
	return Result{
		RunID: applied.RunID, UserID: applied.UserID, SessionID: applied.SessionID,
		ReturnPath: command.ReturnPath, Replayed: applied.Replayed, Credential: browserCredential,
	}, nil
}

func (service *Service) finalizeFailure(
	parent context.Context,
	runID uuid.UUID,
	command Command,
	eventID uuid.UUID,
	category FailureCategory,
) {
	if service == nil || parent == nil || !validFailureCategory(category) {
		return
	}
	timeout := service.operationTimeout
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	defer cancel()
	_ = service.repository.Fail(cleanup, FailureRequest{
		RunID: runID, Category: category, Audit: service.audit(command, eventID),
	})
}

func (service *Service) audit(command Command, eventID uuid.UUID) AuditMetadata {
	return AuditMetadata{
		EventID: eventID, RequestID: command.RequestID, CorrelationID: command.CorrelationID,
		ClientIP: command.ClientIP, UserAgent: command.UserAgent, AuthenticationMethod: "ldap",
	}
}

func (service *Service) currentTime() time.Time {
	return service.now().UTC().Truncate(time.Microsecond)
}

func (service *Service) ids(count int) ([]uuid.UUID, error) {
	result := make([]uuid.UUID, count)
	seen := make(map[uuid.UUID]struct{}, count)
	for index := range result {
		value, err := service.newID()
		if err != nil || !validUUIDv7(value) {
			return nil, ErrUnavailable
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrUnavailable
		}
		seen[value] = struct{}{}
		result[index] = value
	}
	return result, nil
}

func (service *Service) rateDigests(command Command) [3][sha256.Size]byte {
	return [3][sha256.Size]byte{
		service.rateDigest("network", command.ProviderKey, command.ClientIP.String()),
		service.rateDigest("account", command.ProviderKey, strings.ToLower(command.Username)),
		service.rateDigest("provider", command.ProviderKey),
	}
}

func (service *Service) rateDigest(domain string, values ...string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, service.rateDigestKey[:])
	_, _ = mac.Write([]byte("periapsis/platform-ldap-login-rate/v1\x00" + domain))
	for _, value := range values {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write([]byte(value))
	}
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func validCommand(command Command) bool {
	if len(command.ProviderKey) < 3 || len(command.ProviderKey) > 64 ||
		strings.ToLower(command.ProviderKey) != command.ProviderKey || !validProviderKey(command.ProviderKey) ||
		len(command.Username) < 1 || len(command.Username) > 1280 || utf8.RuneCountInString(command.Username) > 320 ||
		len(command.Password) < 1 || len(command.Password) > 8192 ||
		len(command.TOTPCode) > 16 || len(command.UserAgent) < 1 || len(command.UserAgent) > 1024 ||
		!utf8.ValidString(command.UserAgent) || !command.ClientIP.IsValid() ||
		!validUUIDv7(command.RequestID) || !validUUIDv7(command.CorrelationID) {
		return false
	}
	if _, err := identity.NewLDAPUsername(command.Username); err != nil {
		return false
	}
	return validReturnPath(command.ReturnPath)
}

func validProviderKey(value string) bool {
	for index, character := range value {
		if index == 0 {
			if character < 'a' || character > 'z' {
				return false
			}
			continue
		}
		if !((character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validReturnPath(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) ||
		!strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsRune(value, '\\') {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Path == "" || strings.Contains(parsed.Path, "//") ||
		path.Clean(parsed.Path) != parsed.Path || parsed.String() != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validNetworkSnapshot(snapshot NetworkSnapshot, runID uuid.UUID) bool {
	if snapshot.RunID != runID || !validRunState(snapshot.State) {
		return false
	}
	if !snapshot.Allowed {
		return snapshot.State != RunPending
	}
	return snapshot.State == RunPending && validUUIDv7(snapshot.ProviderID) &&
		validUUIDv7(snapshot.BindSecretID) && snapshot.ProviderVersion > 0 &&
		snapshot.ConfigurationRevision > 0 && snapshot.SecurityRevision > 0 &&
		snapshot.MappingRevision > 0 && snapshot.BindSecretRevision > 0 &&
		snapshot.Configuration.JITMode == identityprovider.JITModeExistingIdentity &&
		snapshot.Configuration.NoMatchPolicy == identityprovider.NoMatchPolicyDeny &&
		len(snapshot.Endpoints) > 0 && snapshot.BindSecret.KeyVersion > 0 &&
		len(snapshot.BindSecret.Ciphertext) > 16
}

func validMFASnapshot(snapshot MFASnapshot, network NetworkSnapshot) bool {
	return snapshot.RunID == network.RunID && validUUIDv7(snapshot.UserID) &&
		snapshot.UserAuthenticationRevision > 0 && validUUIDv7(snapshot.ExternalIdentityID) &&
		snapshot.IdentityVersion >= 0 && validUUIDv7(snapshot.TOTP.ID) &&
		snapshot.TOTP.SecurityRevision > 0 && validTOTPSecret(snapshot.TOTP.Secret) &&
		(snapshot.TOTP.LastAcceptedCounter == nil || *snapshot.TOTP.LastAcceptedCounter >= 0) &&
		len(snapshot.Mappings) <= 1024
}

func validTOTPSecret(secret platformoidcauth.DirectProtectedTOTPSecret) bool {
	return secret.KeyVersion > 0 && len(secret.Ciphertext) > 16 && len(secret.Ciphertext) <= 8192 &&
		len(secret.Nonce) >= 12 && len(secret.Nonce) <= 24 && len(secret.AAD) > 0 && len(secret.AAD) <= 1024 &&
		(secret.EncryptionAlgorithm == "aes-256-gcm" || secret.EncryptionAlgorithm == "xchacha20-poly1305") &&
		(secret.OTPAlgorithm == "SHA1" || secret.OTPAlgorithm == "SHA256" || secret.OTPAlgorithm == "SHA512") &&
		(secret.Digits == 6 || secret.Digits == 8) && secret.PeriodSeconds >= 15 && secret.PeriodSeconds <= 120
}

func validTOTPCode(value []byte) bool {
	if len(value) != 6 && len(value) != 8 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func observationProfile(observation identity.LDAPObservation) (Profile, error) {
	username, usernamePresent, err := observation.RevealProfileField(identity.LDAPProfileUsername)
	if err != nil || !usernamePresent {
		return Profile{}, ErrAuthentication
	}
	displayName, displayPresent, err := observation.RevealProfileField(identity.LDAPProfileDisplayName)
	if err != nil || !displayPresent {
		return Profile{}, ErrAuthentication
	}
	profile := Profile{Username: strings.TrimSpace(username), DisplayName: strings.TrimSpace(displayName)}
	if profile.Username == "" || profile.DisplayName == "" {
		return Profile{}, ErrAuthentication
	}
	fields := []struct {
		field identity.LDAPProfileField
		to    **string
	}{
		{identity.LDAPProfileEmail, &profile.Email},
		{identity.LDAPProfileFirstName, &profile.FirstName},
		{identity.LDAPProfileLastName, &profile.LastName},
	}
	for _, field := range fields {
		value, present, revealErr := observation.RevealProfileField(field.field)
		if revealErr != nil {
			return Profile{}, ErrAuthentication
		}
		if !present {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return Profile{}, ErrAuthentication
		}
		if field.field == identity.LDAPProfileEmail {
			value = strings.ToLower(value)
		}
		*field.to = &value
	}
	return profile, nil
}

type canonicalGroup struct {
	value  string
	parsed identity.LDAPDistinguishedName
}

func canonicalGroups(entries []ldapclient.DirectoryEntry) ([]canonicalGroup, error) {
	if len(entries) > 10_000 {
		return nil, ErrAuthentication
	}
	fold := cases.Fold()
	byKey := make(map[string]canonicalGroup, len(entries))
	for _, entry := range entries {
		parsed, err := identity.ParseLDAPDistinguishedName(entry.DistinguishedName)
		if err != nil {
			return nil, ErrAuthentication
		}
		rendered, err := ldap.ParseDN(entry.DistinguishedName)
		if err != nil {
			return nil, ErrAuthentication
		}
		canonical := rendered.String()
		key := fold.String(canonical)
		current, exists := byKey[key]
		if !exists || canonical < current.value {
			byKey[key] = canonicalGroup{value: canonical, parsed: parsed}
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]canonicalGroup, len(keys))
	for index, key := range keys {
		result[index] = byKey[key]
	}
	return result, nil
}

func selectMappings(groups []canonicalGroup, mappings []Mapping) ([]Mapping, error) {
	ordered := append([]Mapping(nil), mappings...)
	slices.SortFunc(ordered, func(left, right Mapping) int {
		if left.Priority != right.Priority {
			return left.Priority - right.Priority
		}
		return slices.Compare(left.ID[:], right.ID[:])
	})
	selectedByRole := make(map[uuid.UUID]Mapping, len(ordered))
	seenRules := make(map[uuid.UUID]struct{}, len(ordered))
	for _, mapping := range ordered {
		if !validMapping(mapping) || mapping.PlatformRoleKey == platformSuperAdminKey {
			return nil, ErrAuthentication
		}
		if _, duplicate := seenRules[mapping.ID]; duplicate {
			return nil, ErrAuthentication
		}
		seenRules[mapping.ID] = struct{}{}
		matcher, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
			Kind: matcherKind(mapping.MatcherType), CaseMode: matcherCaseMode(mapping.CaseSensitive),
			Pattern: mapping.MatcherValue,
		})
		if err != nil {
			return nil, ErrAuthentication
		}
		matched := false
		for _, group := range groups {
			matched, err = matcher.Match(group.parsed)
			if err != nil {
				return nil, ErrAuthentication
			}
			if matched {
				break
			}
		}
		if matched {
			if _, alreadySelected := selectedByRole[mapping.PlatformRoleID]; !alreadySelected {
				selectedByRole[mapping.PlatformRoleID] = mapping
			}
		}
	}
	selected := make([]Mapping, 0, len(selectedByRole))
	for _, mapping := range ordered {
		if winner, ok := selectedByRole[mapping.PlatformRoleID]; ok && winner.ID == mapping.ID {
			selected = append(selected, mapping)
		}
	}
	if len(selected) > maximumSelectedMappings {
		return nil, ErrAuthentication
	}
	return selected, nil
}

func validMapping(mapping Mapping) bool {
	if !validUUIDv7(mapping.ID) || !validUUIDv7(mapping.PlatformRoleID) ||
		!validRoleKey(mapping.PlatformRoleKey) ||
		mapping.Priority < 0 || mapping.Priority > 1_000_000 ||
		(mapping.ReconciliationMode != ReconciliationAuthoritative && mapping.ReconciliationMode != ReconciliationAdditive) {
		return false
	}
	switch mapping.MatcherType {
	case MappingExactDN, MappingExactCN, MappingRegex:
		return true
	default:
		return false
	}
}

func validRoleKey(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !((character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_') {
			return false
		}
	}
	return true
}

func matcherKind(value MappingMatcherType) identity.LDAPGroupMatcherKind {
	switch value {
	case MappingExactDN:
		return identity.LDAPGroupMatcherExactDN
	case MappingExactCN:
		return identity.LDAPGroupMatcherExactCN
	case MappingRegex:
		return identity.LDAPGroupMatcherRegex
	default:
		return 0
	}
}

func matcherCaseMode(caseSensitive bool) identity.LDAPGroupCaseMode {
	if caseSensitive {
		return identity.LDAPGroupCaseSensitive
	}
	return identity.LDAPGroupCaseInsensitive
}

func activeSubjectAlias(aliases []identity.SubjectAlias, activeVersion int16) (identity.SubjectAlias, bool) {
	var result identity.SubjectAlias
	found := false
	for _, alias := range aliases {
		if alias.KeyVersion != activeVersion {
			continue
		}
		if found || alias.Digest == ([sha256.Size]byte{}) {
			return identity.SubjectAlias{}, false
		}
		result = alias
		found = true
	}
	return result, found
}

func validSessionReservation(reservation *federatedauth.ApplyCredentialReservation, at time.Time) bool {
	if reservation == nil || !reservation.Continuation().IsZero() {
		return false
	}
	session := reservation.Session()
	return !session.IsZero() && session.ValidAt(at.Truncate(time.Millisecond)) &&
		session.AuthenticationMethod() == mfa.SessionAuthenticationLDAP
}

func validApplyResult(result ApplyResult, request ApplyRequest) bool {
	if request.Session == nil || result.RunID != request.RunID || result.State != RunSucceeded ||
		result.UserID != request.UserID {
		return false
	}
	session := request.Session.Session()
	return !session.IsZero() && request.Session.Continuation().IsZero() && result.SessionID == session.SessionID()
}

func digestGroups(groups []canonicalGroup) [sha256.Size]byte {
	digest := sha256.New()
	writeDigestField(digest, []byte("periapsis/platform-ldap-groups/v1"))
	writeDigestNumber(digest, uint64(len(groups)))
	for _, group := range groups {
		writeDigestField(digest, []byte(group.value))
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func applyDigest(
	network NetworkSnapshot,
	snapshot MFASnapshot,
	envelope identity.ExternalSubjectEnvelope,
	alias identity.SubjectAlias,
	profile Profile,
	groupsDigest [sha256.Size]byte,
	selected []uuid.UUID,
	counter int64,
	session mfa.SessionReservation,
	completedAt time.Time,
	returnPath string,
) ([sha256.Size]byte, bool) {
	if session.IsZero() || counter < 0 || len(selected) < 1 || len(selected) > maximumSelectedMappings {
		return [sha256.Size]byte{}, false
	}
	digest := sha256.New()
	writeDigestField(digest, []byte("periapsis/platform-ldap-apply/v1"))
	for _, identifier := range []uuid.UUID{
		network.RunID, network.ProviderID, snapshot.UserID, snapshot.ExternalIdentityID,
		snapshot.TOTP.ID, uuid.UUID(session.SessionID()), uuid.UUID(session.FamilyID()),
	} {
		writeDigestField(digest, identifier[:])
	}
	for _, revision := range []uint64{
		uint64(network.ProviderVersion), uint64(network.ConfigurationRevision), uint64(network.SecurityRevision),
		uint64(network.MappingRevision), snapshot.UserAuthenticationRevision, uint64(snapshot.IdentityVersion),
		uint64(alias.KeyVersion), snapshot.TOTP.SecurityRevision, uint64(counter),
	} {
		writeDigestNumber(digest, revision)
	}
	writeDigestField(digest, alias.Digest[:])
	writeDigestField(digest, envelope.Nonce[:])
	writeDigestField(digest, envelope.Ciphertext)
	writeDigestField(digest, []byte(profile.Username))
	writeOptionalDigestString(digest, profile.Email)
	writeDigestField(digest, []byte(profile.DisplayName))
	writeOptionalDigestString(digest, profile.FirstName)
	writeOptionalDigestString(digest, profile.LastName)
	writeDigestField(digest, groupsDigest[:])
	writeDigestNumber(digest, uint64(len(selected)))
	for _, identifier := range selected {
		writeDigestField(digest, identifier[:])
	}
	tokenDigest := session.TokenDigest()
	csrfDigest := session.CSRFDigest()
	writeDigestField(digest, tokenDigest[:])
	writeDigestField(digest, csrfDigest[:])
	writeDigestNumber(digest, uint64(session.IdleExpiresAt().UnixMicro()))
	writeDigestNumber(digest, uint64(session.AbsoluteExpiresAt().UnixMicro()))
	writeDigestNumber(digest, uint64(completedAt.UnixMicro()))
	writeDigestField(digest, []byte(returnPath))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, result != ([sha256.Size]byte{})
}

func writeOptionalDigestString(digest hash.Hash, value *string) {
	if value == nil {
		writeDigestField(digest, nil)
		return
	}
	writeDigestField(digest, []byte(*value))
}

func writeDigestField(digest hash.Hash, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}

func writeDigestNumber(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func mapBeginError(err error) error {
	switch {
	case errors.Is(err, ErrRateLimited):
		return ErrRateLimited
	case errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrAuthentication
	}
}

func mapDirectoryFailure(category ldapclient.DirectoryCategory, err error) (FailureCategory, error) {
	if errors.Is(err, ldapclient.ErrBusy) {
		return FailureRateLimited, ErrRateLimited
	}
	if err != nil {
		return FailureProviderUnavailable, ErrUnavailable
	}
	switch category {
	case ldapclient.DirectoryCategoryCredentialsRejected, ldapclient.DirectoryCategoryUserNotFound,
		ldapclient.DirectoryCategoryUserAmbiguous:
		return FailureCredentialsRejected, ErrAuthentication
	case ldapclient.DirectoryCategoryCancelled:
		return FailureProviderUnavailable, ErrUnavailable
	case ldapclient.DirectoryCategoryDNSFailed, ldapclient.DirectoryCategoryDestinationBlocked,
		ldapclient.DirectoryCategoryConnectTimeout, ldapclient.DirectoryCategoryConnectFailed,
		ldapclient.DirectoryCategoryTLSFailed, ldapclient.DirectoryCategoryCertificateRejected,
		ldapclient.DirectoryCategoryServiceBindRejected:
		return FailureProviderUnavailable, ErrUnavailable
	default:
		return FailureProtocolFailed, ErrUnavailable
	}
}

func classifyLoadError(err error) FailureCategory {
	if errors.Is(err, ErrStaleConfiguration) {
		return FailureStaleConfiguration
	}
	return FailureIdentityUnmatched
}

func mapAuthenticationError(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return ErrUnavailable
	}
	return ErrAuthentication
}

func validFailureCategory(category FailureCategory) bool {
	switch category {
	case FailureCredentialsRejected, FailureAccountDisabled, FailureIdentityUnmatched,
		FailureMappingUnmatched, FailureMFARequired, FailureMFARejected, FailureRateLimited,
		FailureProviderUnavailable, FailureProtocolFailed, FailureStaleConfiguration:
		return true
	default:
		return false
	}
}

func validRunState(state RunState) bool {
	switch state {
	case RunPending, RunSucceeded, RunDenied, RunFailed, RunStale:
		return true
	default:
		return false
	}
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func cloneTOTPSecret(value platformoidcauth.DirectProtectedTOTPSecret) platformoidcauth.DirectProtectedTOTPSecret {
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	value.Nonce = append([]byte(nil), value.Nonce...)
	value.AAD = append([]byte(nil), value.AAD...)
	return value
}

func cloneCounter(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func clearAliases(aliases []identity.SubjectAlias) {
	for index := range aliases {
		clear(aliases[index].Digest[:])
		aliases[index].KeyVersion = 0
	}
	clear(aliases)
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
