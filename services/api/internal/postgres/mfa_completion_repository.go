package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
)

const (
	resolveMFACompletionArtifactSQL     = `select app.resolve_mfa_completion_artifact_v1($1::jsonb)`
	maximumMFACompletionCredentialBytes = 4 * 1024
)

var mfaCompletionResolutionKeys = map[string]struct{}{
	"loadedAt": {}, "artifactKind": {}, "artifactId": {}, "browserDigest": {}, "factorKind": {}, "factorId": {},
	"flow": {}, "tenantId": {}, "userId": {}, "identityEpoch": {}, "resolvedUserId": {},
	"resolvedIdentityEpoch": {}, "sessionId": {}, "sessionFamilyId": {}, "continuationId": {},
	"anchorVersion": {}, "anchorExpiresAt": {}, "action": {}, "audience": {}, "reservationDisposition": {},
	"reservationAuthenticationMethod": {}, "resultAuthenticationMethod": {}, "sourceSessionId": {},
	"sourceSessionFamilyId": {}, "sourceSessionVersion": {}, "sourceAbsoluteExpiresAt": {},
	"continuationReceiptDigest": {},
}

type mfaCompletionLookupWire struct {
	ArtifactKind              string    `json:"artifactKind"`
	ArtifactID                string    `json:"artifactId"`
	BrowserDigest             string    `json:"browserDigest"`
	SelectedFactorKind        string    `json:"selectedFactorKind"`
	SelectedFactorID          string    `json:"selectedFactorId,omitempty"`
	ContinuationReceiptDigest string    `json:"continuationReceiptDigest,omitempty"`
	RequestedAt               time.Time `json:"requestedAt"`
}

// mfaCompletionResolutionWire mirrors the fixed-key protected resolver
// projection. Nullable fields remain pointers so JSON null cannot be confused
// with a present empty value before the domain constructor validates the flow.
type mfaCompletionResolutionWire struct {
	LoadedAt                        time.Time  `json:"loadedAt"`
	ArtifactKind                    string     `json:"artifactKind"`
	ArtifactID                      string     `json:"artifactId"`
	BrowserDigest                   string     `json:"browserDigest"`
	FactorKind                      string     `json:"factorKind"`
	FactorID                        string     `json:"factorId"`
	Flow                            string     `json:"flow"`
	TenantID                        string     `json:"tenantId"`
	UserID                          *string    `json:"userId"`
	IdentityEpoch                   int64      `json:"identityEpoch"`
	ResolvedUserID                  string     `json:"resolvedUserId"`
	ResolvedIdentityEpoch           int64      `json:"resolvedIdentityEpoch"`
	SessionID                       *string    `json:"sessionId"`
	SessionFamilyID                 *string    `json:"sessionFamilyId"`
	ContinuationID                  *string    `json:"continuationId"`
	AnchorVersion                   int64      `json:"anchorVersion"`
	AnchorExpiresAt                 *time.Time `json:"anchorExpiresAt"`
	Action                          string     `json:"action"`
	Audience                        string     `json:"audience"`
	ReservationDisposition          string     `json:"reservationDisposition"`
	ReservationAuthenticationMethod *string    `json:"reservationAuthenticationMethod"`
	ResultAuthenticationMethod      *string    `json:"resultAuthenticationMethod"`
	SourceSessionID                 *string    `json:"sourceSessionId"`
	SourceSessionFamilyID           *string    `json:"sourceSessionFamilyId"`
	SourceSessionVersion            *int64     `json:"sourceSessionVersion"`
	SourceAbsoluteExpiresAt         *time.Time `json:"sourceAbsoluteExpiresAt"`
	ContinuationReceiptDigest       *string    `json:"continuationReceiptDigest"`
}

var _ mfaauth.CompletionTicketSource = (*MFAPlanRepository)(nil)

func (repository *MFAPlanRepository) ResolveMFACompletion(
	ctx context.Context,
	lookup mfaauth.CompletionTicketLookup,
) (mfaauth.CompletionTicketResolutionInput, error) {
	if repository == nil || repository.queryer == nil {
		return mfaauth.CompletionTicketResolutionInput{}, errMFAPersistence
	}
	request, err := mfaCompletionLookupToWire(lookup)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, errMFAPersistence
	}
	payload, err := marshalMFAWire(request)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, errMFAPersistence
	}
	defer clear(payload)
	var raw []byte
	if err := repository.queryer.QueryRow(ctx, resolveMFACompletionArtifactSQL, payload).Scan(&raw); err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, errMFAPersistence
	}
	defer clear(raw)
	var wire mfaCompletionResolutionWire
	if err := unmarshalMFACompletionResolution(raw, &wire); err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, errMFAPersistence
	}
	result, err := mfaCompletionResolutionFromWire(wire)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, errMFAPersistence
	}
	return result, nil
}

func unmarshalMFACompletionResolution(raw []byte, target *mfaCompletionResolutionWire) error {
	if len(raw) == 0 || len(raw) > maximumMFAWireBytes || target == nil {
		return errInvalidMFAWire
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errInvalidMFAWire
	}
	seen := make(map[string]struct{}, len(mfaCompletionResolutionKeys))
	for decoder.More() {
		token, tokenErr := decoder.Token()
		key, keyOK := token.(string)
		_, expected := mfaCompletionResolutionKeys[key]
		_, duplicate := seen[key]
		if tokenErr != nil || !keyOK || !expected || duplicate {
			return errInvalidMFAWire
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errInvalidMFAWire
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != len(mfaCompletionResolutionKeys) {
		return errInvalidMFAWire
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidMFAWire
	}
	return unmarshalMFAWire(raw, target)
}

func mfaCompletionLookupToWire(value mfaauth.CompletionTicketLookup) (mfaCompletionLookupWire, error) {
	artifactID, err := completionArtifactIDToWire(value.ArtifactKind, value.ArtifactID)
	if err != nil {
		return mfaCompletionLookupWire{}, err
	}
	factorID, err := completionRequestedFactorIDToWire(value.ArtifactKind, value.FactorKind, value.FactorID)
	if err != nil {
		return mfaCompletionLookupWire{}, err
	}
	if value.BrowserDigest == ([sha256.Size]byte{}) || value.RequestedAt.IsZero() {
		return mfaCompletionLookupWire{}, errInvalidMFAWire
	}
	request := mfaCompletionLookupWire{
		ArtifactKind: string(value.ArtifactKind), ArtifactID: artifactID,
		BrowserDigest:      base64.StdEncoding.EncodeToString(value.BrowserDigest[:]),
		SelectedFactorKind: string(value.FactorKind), SelectedFactorID: factorID,
		RequestedAt: value.RequestedAt,
	}
	if value.ContinuationReceiptDigest != ([sha256.Size]byte{}) {
		request.ContinuationReceiptDigest = base64.StdEncoding.EncodeToString(value.ContinuationReceiptDigest[:])
	}
	return request, nil
}

func completionArtifactIDToWire(kind mfaauth.CompletionArtifactKind, value []byte) (string, error) {
	switch kind {
	case mfaauth.CompletionArtifactTOTPEnrollment:
		return completionEntityIDToWire(value)
	case mfaauth.CompletionArtifactStepUp, mfaauth.CompletionArtifactWebAuthnRegistration,
		mfaauth.CompletionArtifactWebAuthnAuthentication:
		if len(value) != sha256.Size {
			return "", errInvalidMFAWire
		}
		return base64.StdEncoding.EncodeToString(value), nil
	default:
		return "", errInvalidMFAWire
	}
}

func completionRequestedFactorIDToWire(
	artifact mfaauth.CompletionArtifactKind,
	kind mfaauth.CompletionFactorKind,
	value []byte,
) (string, error) {
	switch artifact {
	case mfaauth.CompletionArtifactTOTPEnrollment:
		if kind == mfaauth.CompletionFactorTOTP && len(value) == 0 {
			return "", nil
		}
	case mfaauth.CompletionArtifactStepUp:
		if kind == mfaauth.CompletionFactorRecovery && len(value) == 0 {
			return "", nil
		}
		if kind == mfaauth.CompletionFactorTOTP {
			return completionEntityIDToWire(value)
		}
	case mfaauth.CompletionArtifactWebAuthnRegistration, mfaauth.CompletionArtifactWebAuthnAuthentication:
		if kind == mfaauth.CompletionFactorPasskey && len(value) > 0 &&
			len(value) <= maximumMFACompletionCredentialBytes {
			return base64.StdEncoding.EncodeToString(value), nil
		}
	}
	return "", errInvalidMFAWire
}

func completionEntityIDToWire(value []byte) (string, error) {
	if len(value) != len(identity.EntityID{}) {
		return "", errInvalidMFAWire
	}
	var identifier identity.EntityID
	copy(identifier[:], value)
	wire := entityIDWire(identifier)
	if wire == "" {
		return "", errInvalidMFAWire
	}
	return wire, nil
}

func mfaCompletionResolutionFromWire(
	value mfaCompletionResolutionWire,
) (mfaauth.CompletionTicketResolutionInput, error) {
	artifactKind := mfaauth.CompletionArtifactKind(value.ArtifactKind)
	factorKind := mfaauth.CompletionFactorKind(value.FactorKind)
	artifactID, err := completionArtifactIDFromWire(artifactKind, value.ArtifactID)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	factorID, err := completionFactorIDFromWire(artifactKind, factorKind, value.FactorID)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	browserDigest, err := completionDigestFromWire(value.BrowserDigest, false)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	receiptDigest := [sha256.Size]byte{}
	if value.ContinuationReceiptDigest != nil {
		receiptDigest, err = completionDigestFromWire(*value.ContinuationReceiptDigest, true)
		if err != nil {
			return mfaauth.CompletionTicketResolutionInput{}, err
		}
	}
	tenantID, err := parseCompletionEntityIDWire(value.TenantID)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	userID, err := completionOptionalEntityIDFromWire(value.UserID)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	resolvedUserID, err := parseCompletionEntityIDWire(value.ResolvedUserID)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	ids, err := completionOptionalEntityIDsFromWire(
		value.SessionID, value.SessionFamilyID, value.ContinuationID,
		value.SourceSessionID, value.SourceSessionFamilyID,
	)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	if value.IdentityEpoch < 0 || value.IdentityEpoch > maximumMFAJSONSafeInteger ||
		value.ResolvedIdentityEpoch < 0 || value.ResolvedIdentityEpoch > maximumMFAJSONSafeInteger ||
		value.AnchorVersion < 0 || value.AnchorVersion >= maximumMFAJSONSafeInteger {
		return mfaauth.CompletionTicketResolutionInput{}, errInvalidMFAWire
	}
	sourceVersion := int64(0)
	if value.SourceSessionVersion != nil {
		sourceVersion = *value.SourceSessionVersion
		if sourceVersion < 0 || sourceVersion >= maximumMFAJSONSafeInteger {
			return mfaauth.CompletionTicketResolutionInput{}, errInvalidMFAWire
		}
	}
	disposition, err := completionReservationDispositionFromWire(value.ReservationDisposition)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	reservationMethod, err := completionReservationMethodFromWire(value.ReservationAuthenticationMethod)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	resultMethod, err := completionResultMethodFromWire(value.ResultAuthenticationMethod)
	if err != nil {
		return mfaauth.CompletionTicketResolutionInput{}, err
	}
	return mfaauth.CompletionTicketResolutionInput{
		LoadedAt: value.LoadedAt.UTC(), ArtifactKind: artifactKind, ArtifactID: artifactID,
		BrowserDigest: browserDigest, FactorKind: factorKind, FactorID: factorID,
		Flow: mfaauth.CompletionFlow(value.Flow), TenantID: tenantID, UserID: userID,
		IdentityEpoch: uint64(value.IdentityEpoch), ResolvedUserID: resolvedUserID,
		ResolvedIdentityEpoch: uint64(value.ResolvedIdentityEpoch), SessionID: ids[0],
		SessionFamilyID: ids[1], ContinuationID: ids[2], AnchorVersion: uint64(value.AnchorVersion),
		AnchorExpiresAt: completionOptionalTime(value.AnchorExpiresAt), Action: value.Action, Audience: value.Audience,
		ContinuationReceiptDigest: receiptDigest, ReservationDisposition: disposition,
		ReservationAuthenticationMethod: reservationMethod, ResultAuthenticationMethod: resultMethod,
		SourceSessionID: ids[3], SourceSessionFamilyID: ids[4], SourceSessionVersion: uint64(sourceVersion),
		SourceAbsoluteExpiresAt: completionOptionalTime(value.SourceAbsoluteExpiresAt),
	}, nil
}

func completionArtifactIDFromWire(kind mfaauth.CompletionArtifactKind, value string) ([]byte, error) {
	if kind == mfaauth.CompletionArtifactTOTPEnrollment {
		identifier, err := parseCompletionEntityIDWire(value)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), identifier[:]...), nil
	}
	if kind != mfaauth.CompletionArtifactStepUp && kind != mfaauth.CompletionArtifactWebAuthnRegistration &&
		kind != mfaauth.CompletionArtifactWebAuthnAuthentication {
		return nil, errInvalidMFAWire
	}
	return completionBase64FromWire(value, sha256.Size, sha256.Size)
}

func completionFactorIDFromWire(
	artifact mfaauth.CompletionArtifactKind,
	kind mfaauth.CompletionFactorKind,
	value string,
) ([]byte, error) {
	if artifact == mfaauth.CompletionArtifactTOTPEnrollment || artifact == mfaauth.CompletionArtifactStepUp {
		if artifact == mfaauth.CompletionArtifactTOTPEnrollment && kind != mfaauth.CompletionFactorTOTP ||
			artifact == mfaauth.CompletionArtifactStepUp && kind != mfaauth.CompletionFactorTOTP &&
				kind != mfaauth.CompletionFactorRecovery {
			return nil, errInvalidMFAWire
		}
		identifier, err := parseCompletionEntityIDWire(value)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), identifier[:]...), nil
	}
	if (artifact == mfaauth.CompletionArtifactWebAuthnRegistration ||
		artifact == mfaauth.CompletionArtifactWebAuthnAuthentication) && kind == mfaauth.CompletionFactorPasskey {
		return completionBase64FromWire(value, 1, maximumMFACompletionCredentialBytes)
	}
	return nil, errInvalidMFAWire
}

func completionDigestFromWire(value string, rejectZero bool) ([sha256.Size]byte, error) {
	decoded, err := completionBase64FromWire(value, sha256.Size, sha256.Size)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	clear(decoded)
	if rejectZero && result == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, errInvalidMFAWire
	}
	return result, nil
}

func completionBase64FromWire(value string, minimum, maximum int) ([]byte, error) {
	if value == "" || len(value) > base64.StdEncoding.EncodedLen(maximum) {
		return nil, errInvalidMFAWire
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, errInvalidMFAWire
	}
	return decoded, nil
}

func completionOptionalEntityIDFromWire(value *string) (identity.EntityID, error) {
	if value == nil {
		return identity.EntityID{}, nil
	}
	return parseCompletionEntityIDWire(*value)
}

func parseCompletionEntityIDWire(value string) (identity.EntityID, error) {
	identifier, err := parseEntityIDWire(value, false)
	if err != nil || entityIDWire(identifier) != value {
		return identity.EntityID{}, errInvalidMFAWire
	}
	return identifier, nil
}

func completionOptionalEntityIDsFromWire(values ...*string) ([5]identity.EntityID, error) {
	var result [5]identity.EntityID
	for index, value := range values {
		identifier, err := completionOptionalEntityIDFromWire(value)
		if err != nil {
			return [5]identity.EntityID{}, err
		}
		result[index] = identifier
	}
	return result, nil
}

func completionReservationDispositionFromWire(value string) (mfaauth.CompletionReservationDisposition, error) {
	switch mfaauth.CompletionReservationDisposition(value) {
	case mfaauth.CompletionReservationNone, mfaauth.CompletionReservationCreate,
		mfaauth.CompletionReservationRotate:
		return mfaauth.CompletionReservationDisposition(value), nil
	default:
		return "", errInvalidMFAWire
	}
}

func completionReservationMethodFromWire(value *string) (mfa.SessionAuthenticationMethod, error) {
	if value == nil {
		return "", nil
	}
	method := mfa.SessionAuthenticationMethod(*value)
	switch method {
	case mfa.SessionAuthenticationPasskey, mfa.SessionAuthenticationTOTP, mfa.SessionAuthenticationRecovery,
		mfa.SessionAuthenticationOIDC, mfa.SessionAuthenticationSAML:
		return method, nil
	default:
		return "", errInvalidMFAWire
	}
}

func completionResultMethodFromWire(value *string) (string, error) {
	if value == nil {
		return "", nil
	}
	switch *value {
	case "bootstrap_totp", string(mfa.SessionAuthenticationPasskey), string(mfa.SessionAuthenticationTOTP),
		string(mfa.SessionAuthenticationRecovery), string(mfa.SessionAuthenticationOIDC),
		string(mfa.SessionAuthenticationSAML), string(mfa.SessionAuthenticationLDAP):
		return *value, nil
	default:
		return "", errInvalidMFAWire
	}
}

func completionOptionalTime(value *time.Time) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.UTC()
}
