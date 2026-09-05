package federatedoidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

type parsedJWK struct {
	summary KeySummary
	key     jose.JSONWebKey
}

func (client *Client) parseJWKS(
	document []byte,
	allowedAlgorithms []SigningAlgorithm,
) ([]KeySummary, []jose.JSONWebKey, error) {
	if validateBoundedJSONObject(document, client.limits.MaxJWKSBytes, client.limits) != nil {
		return nil, nil, ErrJWKSRejected
	}
	object, err := decodeObject(document)
	if err != nil {
		return nil, nil, ErrJWKSRejected
	}
	rawKeys, present := object["keys"]
	trimmedKeys := bytes.TrimSpace(rawKeys)
	if !present || len(trimmedKeys) < 2 || trimmedKeys[0] != '[' {
		return nil, nil, ErrJWKSRejected
	}
	var encodedKeys []json.RawMessage
	if json.Unmarshal(trimmedKeys, &encodedKeys) != nil || len(encodedKeys) == 0 ||
		len(encodedKeys) > client.limits.MaxKeys {
		return nil, nil, ErrJWKSRejected
	}
	allowed := make(map[SigningAlgorithm]struct{}, len(allowedAlgorithms))
	for _, algorithm := range allowedAlgorithms {
		if !supportedSigningAlgorithm(algorithm) {
			return nil, nil, ErrInvalidSnapshot
		}
		allowed[algorithm] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, nil, ErrInvalidSnapshot
	}

	parsed := make([]parsedJWK, 0, len(encodedKeys))
	seenKeyIDs := make(map[string]struct{}, len(encodedKeys))
	seenThumbprints := make(map[[32]byte]struct{}, len(encodedKeys))
	totalCertificates := 0
	for _, encodedKey := range encodedKeys {
		keyObject, decodeErr := decodeObject(encodedKey)
		if decodeErr != nil {
			return nil, nil, ErrJWKSRejected
		}
		keyID, _, decodeErr := decodeStringMember(
			keyObject, "kid", true, client.limits.MaxKeyIDBytes,
		)
		if decodeErr != nil || !validKeyID(keyID) {
			return nil, nil, ErrJWKSRejected
		}
		if _, duplicate := seenKeyIDs[keyID]; duplicate {
			return nil, nil, ErrJWKSRejected
		}
		algorithmText, _, decodeErr := decodeStringMember(keyObject, "alg", true, 16)
		algorithm := SigningAlgorithm(algorithmText)
		if decodeErr != nil || !supportedSigningAlgorithm(algorithm) {
			return nil, nil, ErrJWKSRejected
		}
		if _, allowedAlgorithm := allowed[algorithm]; !allowedAlgorithm {
			return nil, nil, ErrJWKSRejected
		}
		use, usePresent, decodeErr := decodeStringMember(keyObject, "use", false, 16)
		if decodeErr != nil || usePresent && use != "sig" {
			return nil, nil, ErrJWKSRejected
		}
		operations, operationsPresent, decodeErr := decodeStringArrayMember(
			keyObject, "key_ops", false, 8, 32,
		)
		if decodeErr != nil || operationsPresent && (len(operations) != 1 || operations[0] != "verify") {
			return nil, nil, ErrJWKSRejected
		}
		if _, remoteCertificateURL := keyObject["x5u"]; remoteCertificateURL {
			return nil, nil, ErrJWKSRejected
		}
		if validateJWKShape(keyObject, algorithm) != nil {
			return nil, nil, ErrJWKSRejected
		}
		certificateCount, certificateErr := client.validateJWKCertificates(keyObject)
		if certificateErr != nil || totalCertificates+certificateCount > client.limits.MaxCertificates {
			return nil, nil, ErrJWKSRejected
		}
		totalCertificates += certificateCount

		var key jose.JSONWebKey
		if key.UnmarshalJSON(encodedKey) != nil || !key.Valid() || !key.IsPublic() ||
			key.KeyID != keyID || key.Algorithm != algorithmText || key.Use != use ||
			len(key.Certificates) != certificateCount || key.CertificatesURL != nil {
			return nil, nil, ErrJWKSRejected
		}
		keyType, curve, bits, keyErr := validatePublicKey(algorithm, key.Key)
		if keyErr != nil {
			return nil, nil, ErrJWKSRejected
		}
		thumbprintBytes, thumbprintErr := key.Thumbprint(crypto.SHA256)
		if thumbprintErr != nil || len(thumbprintBytes) != 32 {
			return nil, nil, ErrJWKSRejected
		}
		var thumbprint [32]byte
		copy(thumbprint[:], thumbprintBytes)
		clear(thumbprintBytes)
		if _, duplicate := seenThumbprints[thumbprint]; duplicate {
			return nil, nil, ErrJWKSRejected
		}
		seenKeyIDs[keyID] = struct{}{}
		seenThumbprints[thumbprint] = struct{}{}
		parsed = append(parsed, parsedJWK{
			summary: KeySummary{
				KeyID: keyID, Algorithm: algorithm, Type: keyType, Curve: curve,
				Bits: bits, CertificateCount: certificateCount, ThumbprintSHA256: thumbprint,
			},
			key: key,
		})
	}
	slices.SortFunc(parsed, func(left, right parsedJWK) int {
		return bytes.Compare([]byte(left.summary.KeyID), []byte(right.summary.KeyID))
	})
	summaries := make([]KeySummary, len(parsed))
	keys := make([]jose.JSONWebKey, len(parsed))
	for index, value := range parsed {
		summaries[index] = value.summary
		keys[index] = value.key
	}
	return summaries, keys, nil
}

func (client *Client) validateJWKCertificates(object map[string]json.RawMessage) (int, error) {
	if _, present := object["x5c"]; !present {
		return 0, nil
	}
	maximumEncodedBytes := base64.StdEncoding.EncodedLen(client.limits.MaxCertificateBytes)
	certificates, _, err := decodeStringArrayMember(
		object, "x5c", true, client.limits.MaxCertificatesPerKey, maximumEncodedBytes,
	)
	if err != nil {
		return 0, ErrJWKSRejected
	}
	for _, encoded := range certificates {
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(encoded)
		if decodeErr != nil || len(decoded) < minimumCertificateBytes ||
			len(decoded) > client.limits.MaxCertificateBytes ||
			base64.StdEncoding.EncodeToString(decoded) != encoded {
			clear(decoded)
			return 0, ErrJWKSRejected
		}
		clear(decoded)
	}
	return len(certificates), nil
}

func validateJWKShape(object map[string]json.RawMessage, algorithm SigningAlgorithm) error {
	for _, privateMember := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, present := object[privateMember]; present {
			return ErrJWKSRejected
		}
	}
	keyType, _, err := decodeStringMember(object, "kty", true, 8)
	if err != nil {
		return ErrJWKSRejected
	}
	switch algorithm {
	case SigningRS256, SigningRS384, SigningRS512, SigningPS256, SigningPS384, SigningPS512:
		if keyType != "RSA" || validateBase64URLIntegerMember(
			object, "n", minimumRSAKeyBits/8, maximumRSAKeyBits/8,
		) != nil || validateBase64URLIntegerMember(object, "e", 1, 8) != nil {
			return ErrJWKSRejected
		}
	case SigningES256, SigningES384, SigningES512:
		curve, _, decodeErr := decodeStringMember(object, "crv", true, 8)
		expectedCurve, coordinateBytes := expectedECProfile(algorithm)
		if keyType != "EC" || decodeErr != nil || curve != expectedCurve ||
			validateBase64URLMember(object, "x", coordinateBytes, coordinateBytes) != nil ||
			validateBase64URLMember(object, "y", coordinateBytes, coordinateBytes) != nil {
			return ErrJWKSRejected
		}
	case SigningEdDSA:
		curve, _, decodeErr := decodeStringMember(object, "crv", true, 16)
		if keyType != "OKP" || decodeErr != nil || curve != "Ed25519" ||
			validateBase64URLMember(object, "x", ed25519.PublicKeySize, ed25519.PublicKeySize) != nil {
			return ErrJWKSRejected
		}
	default:
		return ErrJWKSRejected
	}
	return nil
}

func validateBase64URLIntegerMember(
	object map[string]json.RawMessage,
	name string,
	minimumBytes int,
	maximumBytes int,
) error {
	decoded, err := decodeBase64URLMember(object, name, minimumBytes, maximumBytes)
	if err != nil || len(decoded) == 0 || decoded[0] == 0 {
		clear(decoded)
		return ErrJWKSRejected
	}
	clear(decoded)
	return nil
}

func validateBase64URLMember(
	object map[string]json.RawMessage,
	name string,
	minimumBytes int,
	maximumBytes int,
) error {
	decoded, err := decodeBase64URLMember(object, name, minimumBytes, maximumBytes)
	clear(decoded)
	return err
}

func decodeBase64URLMember(
	object map[string]json.RawMessage,
	name string,
	minimumBytes int,
	maximumBytes int,
) ([]byte, error) {
	maximumEncodedBytes := base64.RawURLEncoding.EncodedLen(maximumBytes)
	encoded, _, err := decodeStringMember(object, name, true, maximumEncodedBytes)
	if err != nil || strings.ContainsRune(encoded, '=') {
		return nil, ErrJWKSRejected
	}
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if decodeErr != nil || len(decoded) < minimumBytes || len(decoded) > maximumBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrJWKSRejected
	}
	return decoded, nil
}

func validKeyID(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for index := range value {
		character := value[index]
		if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func validatePublicKey(
	algorithm SigningAlgorithm,
	value any,
) (KeyType, string, int, error) {
	switch algorithm {
	case SigningRS256, SigningRS384, SigningRS512, SigningPS256, SigningPS384, SigningPS512:
		key, ok := value.(*rsa.PublicKey)
		if !ok || key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 ||
			key.N.BitLen() < minimumRSAKeyBits || key.N.BitLen() > maximumRSAKeyBits ||
			key.E < 3 || key.E > math.MaxInt32 || key.E&1 == 0 {
			return "", "", 0, ErrJWKSRejected
		}
		return KeyTypeRSA, "", key.N.BitLen(), nil
	case SigningES256, SigningES384, SigningES512:
		key, ok := value.(*ecdsa.PublicKey)
		if !ok || key == nil || key.Curve == nil || key.X == nil || key.Y == nil ||
			!key.Curve.IsOnCurve(key.X, key.Y) {
			return "", "", 0, ErrJWKSRejected
		}
		curve := key.Curve.Params().Name
		expectedCurve, _ := expectedECProfile(algorithm)
		if curve != expectedCurve {
			return "", "", 0, ErrJWKSRejected
		}
		return KeyTypeEC, curve, key.Curve.Params().BitSize, nil
	case SigningEdDSA:
		key, ok := value.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return "", "", 0, ErrJWKSRejected
		}
		return KeyTypeEd25519, "Ed25519", ed25519.PublicKeySize * 8, nil
	default:
		return "", "", 0, ErrJWKSRejected
	}
}

func expectedECProfile(algorithm SigningAlgorithm) (string, int) {
	switch algorithm {
	case SigningES256:
		return "P-256", 32
	case SigningES384:
		return "P-384", 48
	case SigningES512:
		return "P-521", 66
	default:
		return "", 0
	}
}
