package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

var ErrInvalidVerifierOptions = errors.New("invalid WebAuthn verifier options")

// AttestationMetadataSource returns one already-pinned FIDO metadata provider
// for an immutable revision. It must not perform ambient network I/O.
type AttestationMetadataSource interface {
	WebAuthnMetadataProvider(context.Context, uint64) (metadata.Provider, error)
}

type LibraryVerifierOptions struct {
	Metadata AttestationMetadataSource
}

// LibraryVerifier implements the cryptographic verifier port with the
// maintained go-webauthn protocol implementation. Periapsis still performs
// independent lifecycle, tenant, counter, RP, origin, and policy checks.
type LibraryVerifier struct {
	metadata AttestationMetadataSource
}

func NewLibraryVerifier(options LibraryVerifierOptions) (*LibraryVerifier, error) {
	return &LibraryVerifier{metadata: options.Metadata}, nil
}

func (verifier *LibraryVerifier) VerifyRegistration(
	ctx context.Context,
	request RegistrationVerificationRequest,
) (RegistrationProof, error) {
	if verifier == nil || ctx == nil || ctx.Err() != nil || !validVerifierRegistrationRequest(request) ||
		validateDuplicateSafeObject(request.ClientDataJSON, 8, 128) != nil {
		return RegistrationProof{}, ErrVerificationRejected
	}
	extensions, discoverable, err := parseRegistrationExtensions(request.ClientExtensionResults, request.Policy.ResidentKey)
	if err != nil {
		return RegistrationProof{}, ErrVerificationRejected
	}
	metadataProvider, trustedRevision, err := verifier.metadataForPolicy(ctx, request.Policy)
	if err != nil {
		return RegistrationProof{}, ErrVerificationRejected
	}
	raw := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(request.CredentialID),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: request.CredentialID, ClientExtensionResults: extensions,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: request.ClientDataJSON},
			AttestationObject:     request.AttestationObject,
			Transports:            libraryTransportStrings(request.Transports),
		},
	}
	parsed, err := raw.Parse()
	if err != nil || !bytes.Equal(parsed.RawID, request.CredentialID) {
		return RegistrationProof{}, ErrVerificationRejected
	}
	challenge, err := validatedChallenge(parsed.Response.CollectedClientData.Challenge, request.ChallengeDigest)
	if err != nil {
		return RegistrationProof{}, ErrVerificationRejected
	}
	verifyUser := request.Policy.UserVerification == UserVerificationRequired
	clientDataHash, err := parsed.Verify(
		challenge, request.RPID, request.AllowedOrigins, nil,
		protocol.TopOriginExplicitVerificationMode, false, verifyUser,
		request.Policy.RequireUserPresence, metadataProvider, webauthnlib.CredentialParametersDefault(),
	)
	if err != nil || ctx.Err() != nil {
		clear(clientDataHash)
		return RegistrationProof{}, ErrVerificationRejected
	}
	credential, err := webauthnlib.NewCredential(clientDataHash, parsed)
	clear(clientDataHash)
	if err != nil || credential == nil || !bytes.Equal(credential.ID, request.CredentialID) ||
		len(credential.PublicKey) < minimumPublicKeyBytes || len(credential.PublicKey) > maximumPublicKeyBytes ||
		len(credential.Authenticator.AAGUID) != 16 {
		return RegistrationProof{}, ErrVerificationRejected
	}
	attestationType, trusted := normalizeAttestationResult(request.Policy.Attestation, credential.AttestationType, trustedRevision != 0)
	if attestationType == 0 {
		return RegistrationProof{}, ErrVerificationRejected
	}
	flags := parsed.Response.AttestationObject.AuthData.Flags
	proof := RegistrationProof{
		ChallengeDigest: request.ChallengeDigest,
		Origin:          parsed.Response.CollectedClientData.Origin,
		UserPresent:     flags.HasUserPresent(), UserVerified: flags.HasUserVerified(),
		CrossOrigin:  parsed.Response.CollectedClientData.CrossOrigin,
		CredentialID: append([]byte(nil), credential.ID...), PublicKey: append([]byte(nil), credential.PublicKey...),
		SignCount: parsed.Response.AttestationObject.AuthData.Counter, Discoverable: discoverable,
		BackupEligible: flags.HasBackupEligible(), BackedUp: flags.HasBackupState(),
		Transports:        normalizeLibraryTransports(credential.Transport),
		AttestationFormat: credential.AttestationFormat, AttestationType: attestationType,
		AttestationTrusted: trusted, MetadataRevision: trustedRevision,
	}
	copy(proof.RPIDHash[:], parsed.Response.AttestationObject.AuthData.RPIDHash)
	copy(proof.AAGUID[:], credential.Authenticator.AAGUID)
	return proof, nil
}

func (verifier *LibraryVerifier) VerifyAuthentication(
	ctx context.Context,
	request AuthenticationVerificationRequest,
) (AuthenticationProof, error) {
	if verifier == nil || ctx == nil || ctx.Err() != nil || !validVerifierAuthenticationRequest(request) ||
		validateDuplicateSafeObject(request.ClientDataJSON, 8, 128) != nil {
		return AuthenticationProof{}, ErrVerificationRejected
	}
	raw := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(request.CredentialID),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: request.CredentialID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: request.ClientDataJSON},
			AuthenticatorData:     request.AuthenticatorData, Signature: request.Signature,
			UserHandle: request.UserHandle,
		},
	}
	parsed, err := raw.Parse()
	if err != nil || !bytes.Equal(parsed.RawID, request.CredentialID) {
		return AuthenticationProof{}, ErrVerificationRejected
	}
	challenge, err := validatedChallenge(parsed.Response.CollectedClientData.Challenge, request.ChallengeDigest)
	if err != nil {
		return AuthenticationProof{}, ErrVerificationRejected
	}
	verifyUser := request.Policy.UserVerification == UserVerificationRequired
	if err := parsed.Verify(
		challenge, request.RPID, "", request.AllowedOrigins, nil,
		protocol.TopOriginExplicitVerificationMode, false, verifyUser,
		request.Policy.RequireUserPresence, request.Credential.PublicKey,
	); err != nil || ctx.Err() != nil {
		return AuthenticationProof{}, ErrVerificationRejected
	}
	flags := parsed.Response.AuthenticatorData.Flags
	proof := AuthenticationProof{
		ChallengeDigest: request.ChallengeDigest, Origin: parsed.Response.CollectedClientData.Origin,
		UserPresent: flags.HasUserPresent(), UserVerified: flags.HasUserVerified(),
		CrossOrigin:    parsed.Response.CollectedClientData.CrossOrigin,
		CredentialID:   append([]byte(nil), parsed.RawID...),
		UserHandle:     append([]byte(nil), parsed.Response.UserHandle...),
		SignCount:      parsed.Response.AuthenticatorData.Counter,
		BackupEligible: flags.HasBackupEligible(), BackedUp: flags.HasBackupState(),
	}
	copy(proof.RPIDHash[:], parsed.Response.AuthenticatorData.RPIDHash)
	return proof, nil
}

func (verifier *LibraryVerifier) metadataForPolicy(
	ctx context.Context,
	policy CeremonyPolicy,
) (metadata.Provider, uint64, error) {
	if policy.Attestation == AttestationNone {
		if policy.MetadataRevision != 0 {
			return nil, 0, ErrVerificationRejected
		}
		return nil, 0, nil
	}
	if verifier.metadata == nil || policy.MetadataRevision == 0 {
		return nil, 0, ErrVerificationRejected
	}
	provider, err := verifier.metadata.WebAuthnMetadataProvider(ctx, policy.MetadataRevision)
	if err != nil || provider == nil {
		return nil, 0, ErrVerificationRejected
	}
	return provider, policy.MetadataRevision, nil
}

func normalizeAttestationResult(policy AttestationPolicy, libraryType string, metadataTrusted bool) (AttestationType, bool) {
	switch policy {
	case AttestationNone:
		if libraryType == string(metadata.None) {
			return AttestationTypeNone, false
		}
	case AttestationDirect:
		if metadataTrusted && (libraryType == string(metadata.BasicFull) || libraryType == string(metadata.AttCA) ||
			libraryType == string(metadata.AnonCA)) {
			return AttestationTypeBasic, true
		}
	case AttestationEnterprise:
		if metadataTrusted && (libraryType == string(metadata.BasicFull) || libraryType == string(metadata.AttCA)) {
			return AttestationTypeEnterprise, true
		}
	}
	return 0, false
}

func validatedChallenge(encoded string, expected [sha256.Size]byte) (string, error) {
	if encoded == "" || strings.ContainsRune(encoded, '=') {
		return "", ErrVerificationRejected
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) < 16 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		clear(raw)
		return "", ErrVerificationRejected
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	if subtle.ConstantTimeCompare(digest[:], expected[:]) != 1 {
		return "", ErrVerificationRejected
	}
	return encoded, nil
}

func validVerifierRegistrationRequest(request RegistrationVerificationRequest) bool {
	return validVerifierRP(request.RPID, request.AllowedOrigins) &&
		len(request.CredentialID) >= minimumCredentialIDBytes && len(request.CredentialID) <= maximumCredentialIDBytes &&
		len(request.ClientDataJSON) != 0 && len(request.ClientDataJSON) <= maximumResponseBytes &&
		len(request.AttestationObject) != 0 && len(request.AttestationObject) <= maximumResponseBytes &&
		len(request.ClientExtensionResults) <= maximumResponseBytes && validVerifierTransports(request.Transports) &&
		request.Policy.RequireUserPresence &&
		(request.Policy.UserVerification == UserVerificationPreferred || request.Policy.UserVerification == UserVerificationRequired) &&
		(request.Policy.ResidentKey == ResidentKeyPreferred || request.Policy.ResidentKey == ResidentKeyRequired) &&
		(request.Policy.Attestation == AttestationNone && request.Policy.MetadataRevision == 0 ||
			(request.Policy.Attestation == AttestationDirect || request.Policy.Attestation == AttestationEnterprise) &&
				request.Policy.MetadataRevision > 0)
}

func validVerifierAuthenticationRequest(request AuthenticationVerificationRequest) bool {
	return validVerifierRP(request.RPID, request.AllowedOrigins) &&
		len(request.CredentialID) >= minimumCredentialIDBytes && len(request.CredentialID) <= maximumCredentialIDBytes &&
		bytes.Equal(request.CredentialID, request.Credential.ID) &&
		len(request.Credential.PublicKey) >= minimumPublicKeyBytes && len(request.Credential.PublicKey) <= maximumPublicKeyBytes &&
		len(request.ClientDataJSON) != 0 && len(request.ClientDataJSON) <= maximumResponseBytes &&
		len(request.AuthenticatorData) != 0 && len(request.AuthenticatorData) <= maximumResponseBytes &&
		len(request.Signature) != 0 && len(request.Signature) <= maximumResponseBytes &&
		len(request.UserHandle) <= stableUserHandleBytes &&
		request.Policy.RequireUserPresence &&
		(request.Policy.UserVerification == UserVerificationPreferred || request.Policy.UserVerification == UserVerificationRequired) &&
		(request.Policy.ResidentKey == ResidentKeyPreferred || request.Policy.ResidentKey == ResidentKeyRequired) &&
		request.Policy.Attestation == AttestationNone && request.Policy.MetadataRevision == 0
}

func validVerifierRP(rpID string, origins []string) bool {
	if !validRPID(rpID) || len(origins) == 0 || len(origins) > maximumOrigins {
		return false
	}
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		if !validOrigin(origin, rpID) {
			return false
		}
		if _, duplicate := seen[origin]; duplicate {
			return false
		}
		seen[origin] = struct{}{}
	}
	return true
}

func validVerifierTransports(values []CredentialTransport) bool {
	normalized, ok := normalizeTransports(values)
	return ok && slices.Equal(normalized, values)
}

func parseRegistrationExtensions(
	raw []byte,
	requirement ResidentKeyRequirement,
) (protocol.AuthenticationExtensionsClientOutputs, bool, error) {
	if len(raw) == 0 {
		if requirement == ResidentKeyRequired {
			return nil, false, ErrVerificationRejected
		}
		return protocol.AuthenticationExtensionsClientOutputs{}, false, nil
	}
	if validateDuplicateSafeObject(raw, 4, 8) != nil {
		return nil, false, ErrVerificationRejected
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != 1 {
		return nil, false, ErrVerificationRejected
	}
	credProps, ok := object["credProps"]
	if !ok {
		return nil, false, ErrVerificationRejected
	}
	var properties map[string]json.RawMessage
	if json.Unmarshal(credProps, &properties) != nil || len(properties) != 1 {
		return nil, false, ErrVerificationRejected
	}
	rawResident, ok := properties["rk"]
	if !ok {
		return nil, false, ErrVerificationRejected
	}
	var resident bool
	if json.Unmarshal(rawResident, &resident) != nil || requirement == ResidentKeyRequired && !resident {
		return nil, false, ErrVerificationRejected
	}
	var outputs protocol.AuthenticationExtensionsClientOutputs
	if json.Unmarshal(raw, &outputs) != nil {
		return nil, false, ErrVerificationRejected
	}
	return outputs, resident, nil
}

func libraryTransportStrings(values []CredentialTransport) []string {
	result := make([]string, len(values))
	for index, value := range values {
		if value == TransportSmartCard {
			result[index] = string(protocol.SmartCard)
		} else {
			result[index] = string(value)
		}
	}
	return result
}

func normalizeLibraryTransports(values []protocol.AuthenticatorTransport) []CredentialTransport {
	result := make([]CredentialTransport, 0, len(values))
	for _, value := range values {
		var transport CredentialTransport
		switch value {
		case protocol.USB:
			transport = TransportUSB
		case protocol.NFC:
			transport = TransportNFC
		case protocol.BLE:
			transport = TransportBLE
		case protocol.Internal:
			transport = TransportInternal
		case protocol.Hybrid:
			transport = TransportHybrid
		case protocol.SmartCard:
			transport = TransportSmartCard
		default:
			continue
		}
		if !slices.Contains(result, transport) {
			result = append(result, transport)
		}
	}
	slices.Sort(result)
	return result
}

func validateDuplicateSafeObject(document []byte, maximumDepth, maximumValues int) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	values := 0
	var consume func(int) error
	consume = func(depth int) error {
		if depth > maximumDepth {
			return ErrVerificationRejected
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrVerificationRejected
		}
		values++
		if values > maximumValues {
			return ErrVerificationRejected
		}
		delimiter, composite := token.(json.Delim)
		if depth == 1 && (!composite || delimiter != '{') {
			return ErrVerificationRejected
		}
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				nameToken, nameErr := decoder.Token()
				name, ok := nameToken.(string)
				if nameErr != nil || !ok {
					return ErrVerificationRejected
				}
				if _, duplicate := seen[name]; duplicate {
					return ErrVerificationRejected
				}
				seen[name] = struct{}{}
				if err := consume(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrVerificationRejected
			}
		case '[':
			for decoder.More() {
				if err := consume(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrVerificationRejected
			}
		default:
			return ErrVerificationRejected
		}
		return nil
	}
	if err := consume(1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrVerificationRejected
	}
	return nil
}
