package federatedoidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

type jwksCorpusCase struct {
	document     func(*testing.T) []byte
	mutateLimits func(*Limits)
}

func TestJWKSHostileCorpusFailsClosed(t *testing.T) {
	fromKey := func(mutate func(map[string]any)) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			key := rsaJWK("key-rsa-primary", SigningRS256)
			mutate(key)
			return jwksDocumentFromKeys(t, key)
		}
	}
	fromKeys := func(build func(*testing.T) []any) func(*testing.T) []byte {
		return func(t *testing.T) []byte { return jwksDocumentFromKeys(t, build(t)...) }
	}
	rsaModulus := func(bytesCount int, last byte) string {
		value := make([]byte, bytesCount)
		value[0] = 0x80
		value[len(value)-1] = last
		return base64.RawURLEncoding.EncodeToString(value)
	}

	tests := map[string]jwksCorpusCase{
		"duplicate top-level keys": {
			document: func(t *testing.T) []byte {
				return appendJSONObjectMember(t, validJWKSDocument(t), `"keys":[]`)
			},
		},
		"duplicate nested kid": {
			document: func(t *testing.T) []byte {
				key := appendJSONObjectMember(t, marshalJSON(t, rsaJWK("key-rsa-primary", SigningRS256)), `"kid":"second"`)
				return rawJWKSWithKey(t, key)
			},
		},
		"top-level array": {
			document: func(*testing.T) []byte { return []byte(`[]`) },
		},
		"trailing JSON": {
			document: func(t *testing.T) []byte {
				return append(jwksDocumentFromKeys(t, rsaJWK("key-rsa-primary", SigningRS256)), []byte(` {}`)...)
			},
		},
		"excessive depth": {
			document:     fromKey(func(key map[string]any) { key["extension"] = map[string]any{"nested": map[string]any{"value": 1}} }),
			mutateLimits: func(limits *Limits) { limits.MaxJSONDepth = 4 },
		},
		"excessive values": {
			document: fromKey(func(key map[string]any) {
				key["extension"] = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
			}),
			mutateLimits: func(limits *Limits) { limits.MaxJSONValues = 32 },
		},
		"excessive object members": {
			document: fromKey(func(key map[string]any) {
				key["extension"] = map[string]any{
					"a": 1, "b": 2, "c": 3, "d": 4, "e": 5,
					"f": 6, "g": 7, "h": 8, "i": 9, "j": 10,
				}
			}),
			mutateLimits: func(limits *Limits) { limits.MaxJSONObjectMembers = 16 },
		},
		"excessive array items": {
			document: fromKey(func(key map[string]any) {
				key["extension"] = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			}),
			mutateLimits: func(limits *Limits) { limits.MaxJSONArrayItems = 16 },
		},
		"excessive string": {
			document:     fromKey(func(key map[string]any) { key["extension"] = strings.Repeat("x", 129) }),
			mutateLimits: func(limits *Limits) { limits.MaxJSONStringBytes = 128 },
		},
		"excessive document bytes": {
			document:     fromKey(func(key map[string]any) { key["extension"] = strings.Repeat("x", 600) }),
			mutateLimits: func(limits *Limits) { limits.MaxJWKSBytes = minimumJWKSBytes },
		},
		"missing keys": {
			document: func(t *testing.T) []byte { return marshalJSON(t, map[string]any{"other": []any{}}) },
		},
		"null keys": {
			document: func(t *testing.T) []byte { return marshalJSON(t, map[string]any{"keys": nil}) },
		},
		"object keys": {
			document: func(t *testing.T) []byte { return marshalJSON(t, map[string]any{"keys": map[string]any{}}) },
		},
		"empty keys": {
			document: func(t *testing.T) []byte { return jwksDocumentFromKeys(t) },
		},
		"too many keys": {
			document: fromKeys(func(*testing.T) []any {
				return []any{rsaJWK("key-rsa-primary", SigningRS256), ecJWK("key-ec-primary", SigningES256)}
			}),
			mutateLimits: func(limits *Limits) { limits.MaxKeys = 1 },
		},
		"duplicate kid": {
			document: fromKeys(func(*testing.T) []any {
				return []any{rsaJWK("same-key-id", SigningRS256), ecJWK("same-key-id", SigningES256)}
			}),
		},
		"ambiguous duplicate public key": {
			document: fromKeys(func(*testing.T) []any {
				return []any{rsaJWK("first-key-id", SigningRS256), rsaJWK("second-key-id", SigningRS256)}
			}),
		},
		"missing kid": {
			document: fromKey(func(key map[string]any) { delete(key, "kid") }),
		},
		"null kid": {
			document: fromKey(func(key map[string]any) { key["kid"] = nil }),
		},
		"empty kid": {
			document: fromKey(func(key map[string]any) { key["kid"] = "" }),
		},
		"space in kid": {
			document: fromKey(func(key map[string]any) { key["kid"] = "key id" }),
		},
		"non-ASCII kid": {
			document: fromKey(func(key map[string]any) { key["kid"] = "chiave-é" }),
		},
		"escape byte in kid": {
			document: fromKey(func(key map[string]any) { key["kid"] = `key\id` }),
		},
		"oversized kid": {
			document: fromKey(func(key map[string]any) { key["kid"] = strings.Repeat("k", 129) }),
		},
		"missing alg": {
			document: fromKey(func(key map[string]any) { delete(key, "alg") }),
		},
		"missing key type": {
			document: fromKey(func(key map[string]any) { delete(key, "kty") }),
		},
		"wrong key type label": {
			document: fromKey(func(key map[string]any) { key["kty"] = "EC" }),
		},
		"none alg": {
			document: fromKey(func(key map[string]any) { key["alg"] = "none" }),
		},
		"unconfigured alg": {
			document: fromKey(func(key map[string]any) { key["alg"] = string(SigningRS384) }),
		},
		"algorithm and key type mismatch": {
			document: fromKey(func(key map[string]any) { key["alg"] = string(SigningES256) }),
		},
		"symmetric key": {
			document: func(t *testing.T) []byte {
				return jwksDocumentFromKeys(t, map[string]any{
					"kty": "oct", "kid": "symmetric-key", "alg": string(SigningRS256),
					"use": "sig", "k": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
				})
			},
		},
		"private RSA key": {
			document: fromKey(func(key map[string]any) { key["d"] = base64.RawURLEncoding.EncodeToString([]byte{1}) }),
		},
		"encryption use": {
			document: fromKey(func(key map[string]any) { key["use"] = "enc" }),
		},
		"null use": {
			document: fromKey(func(key map[string]any) { key["use"] = nil }),
		},
		"sign key operation": {
			document: fromKey(func(key map[string]any) { key["key_ops"] = []string{"sign"} }),
		},
		"multiple key operations": {
			document: fromKey(func(key map[string]any) { key["key_ops"] = []string{"verify", "sign"} }),
		},
		"duplicate key operation": {
			document: fromKey(func(key map[string]any) { key["key_ops"] = []string{"verify", "verify"} }),
		},
		"remote certificate URL": {
			document: fromKey(func(key map[string]any) { key["x5u"] = "https://" + testHostileSentinel }),
		},
		"small RSA modulus": {
			document: fromKey(func(key map[string]any) { key["n"] = rsaModulus(128, 1) }),
		},
		"padded RSA modulus encoding": {
			document: fromKey(func(key map[string]any) { key["n"] = key["n"].(string) + "==" }),
		},
		"leading-zero RSA modulus": {
			document: fromKey(func(key map[string]any) {
				modulus := make([]byte, minimumRSAKeyBits/8+1)
				modulus[1] = 0x80
				modulus[len(modulus)-1] = 1
				key["n"] = base64.RawURLEncoding.EncodeToString(modulus)
			}),
		},
		"oversized RSA modulus": {
			document: fromKey(func(key map[string]any) { key["n"] = rsaModulus(maximumRSAKeyBits/8+1, 1) }),
		},
		"even RSA modulus": {
			document: fromKey(func(key map[string]any) { key["n"] = rsaModulus(minimumRSAKeyBits/8, 2) }),
		},
		"even RSA exponent": {
			document: fromKey(func(key map[string]any) { key["e"] = encodedExponent([]byte{2}) }),
		},
		"EC key with RSA algorithm": {
			document: func(t *testing.T) []byte {
				key := ecJWK("key-ec-primary", SigningES256)
				key["alg"] = string(SigningRS256)
				return jwksDocumentFromKeys(t, key)
			},
		},
		"EC point off curve": {
			document: func(t *testing.T) []byte {
				key := ecJWK("key-ec-primary", SigningES256)
				key["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
				return jwksDocumentFromKeys(t, key)
			},
		},
		"short EC coordinate": {
			document: func(t *testing.T) []byte {
				key := ecJWK("key-ec-primary", SigningES256)
				coordinate, err := base64.RawURLEncoding.DecodeString(key["x"].(string))
				if err != nil {
					t.Fatal(err)
				}
				key["x"] = base64.RawURLEncoding.EncodeToString(coordinate[1:])
				return jwksDocumentFromKeys(t, key)
			},
		},
		"short Ed25519 key": {
			document: func(t *testing.T) []byte {
				key := ed25519JWK("key-ed25519-primary")
				key["x"] = base64.RawURLEncoding.EncodeToString(make([]byte, 31))
				return jwksDocumentFromKeys(t, key)
			},
		},
		"padded Ed25519 encoding": {
			document: func(t *testing.T) []byte {
				key := ed25519JWK("key-ed25519-primary")
				key["x"] = key["x"].(string) + "="
				return jwksDocumentFromKeys(t, key)
			},
		},
		"malformed certificate": {
			document: fromKey(func(key map[string]any) { key["x5c"] = []string{"%%%"} }),
		},
		"undersized certificate": {
			document: fromKey(func(key map[string]any) {
				key["x5c"] = []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, minimumCertificateBytes-1))}
			}),
		},
		"oversized certificate": {
			document: fromKey(func(key map[string]any) {
				key["x5c"] = []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, DefaultLimits().MaxCertificateBytes+1))}
			}),
		},
		"too many certificates per key": {
			document: fromKey(func(key map[string]any) { key["x5c"] = []string{"a", "b", "c", "d", "e"} }),
		},
		"certificate public key mismatch": {
			document: func(t *testing.T) []byte {
				key := rsaJWK("key-rsa-primary", SigningRS256)
				key["x5c"] = []string{ed25519Certificate(t)}
				return jwksDocumentFromKeys(t, key)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			discoveryDocument := validDiscoveryDocument(t)
			jwksDocument := test.document(t)
			client, _ := newTrustTestClient(t, []federatedhttp.Result{
				successfulResult(federatedhttp.DocumentOIDCDiscovery, discoveryDocument),
				successfulResult(federatedhttp.DocumentOIDCJWKS, jwksDocument),
			}, test.mutateLimits)
			discovery := fetchValidDiscovery(t, client)
			_, err := client.FetchJWKS(context.Background(), discovery, testJWKSRev)
			if !errors.Is(err, ErrJWKSRejected) {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), testHostileSentinel) {
				t.Fatal("JWKS rejection leaked hostile document content")
			}
		})
	}
}
