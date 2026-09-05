package federatedoidc

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

type discoveryCorpusCase struct {
	document     func(*testing.T) []byte
	mutateLimits func(*Limits)
	want         error
}

func TestDiscoveryHostileCorpusFailsClosed(t *testing.T) {
	fromObject := func(mutate func(map[string]any)) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			object := validDiscoveryObject()
			mutate(object)
			return marshalJSON(t, object)
		}
	}
	validWithRawMember := func(member string) func(*testing.T) []byte {
		return func(t *testing.T) []byte {
			return appendJSONObjectMember(t, validDiscoveryDocument(t), member)
		}
	}

	tests := map[string]discoveryCorpusCase{
		"issuer byte mismatch": {
			document: fromObject(func(object map[string]any) { object["issuer"] = testIssuer + "/" }),
			want:     ErrIssuerMismatch,
		},
		"duplicate top-level issuer": {
			document: validWithRawMember(`"issuer":"` + testIssuer + `"`),
		},
		"escaped duplicate nested member": {
			document: validWithRawMember(`"extension":{"name":1,"na\u006de":2}`),
		},
		"invalid utf8": {
			document: func(t *testing.T) []byte {
				document := validDiscoveryDocument(t)
				return append(document, 0xff)
			},
		},
		"top-level array": {
			document: func(*testing.T) []byte { return []byte(`[{"issuer":"value"}]`) },
		},
		"trailing JSON": {
			document: func(t *testing.T) []byte { return append(validDiscoveryDocument(t), []byte(` {}`)...) },
		},
		"excessive depth": {
			document:     validWithRawMember(`"extension":{"nested":{"value":1}}`),
			mutateLimits: func(limits *Limits) { limits.MaxJSONDepth = 3 },
		},
		"excessive values": {
			document:     validWithRawMember(`"extension":[1,2,3]`),
			mutateLimits: func(limits *Limits) { limits.MaxJSONValues = 32 },
		},
		"excessive object members": {
			document:     validWithRawMember(`"extension":{"first":1}`),
			mutateLimits: func(limits *Limits) { limits.MaxJSONObjectMembers = 16 },
		},
		"excessive array items": {
			document:     validWithRawMember(`"extension":[1,2,3,4]`),
			mutateLimits: func(limits *Limits) { limits.MaxJSONArrayItems = 16 },
		},
		"excessive string": {
			document:     fromObject(func(object map[string]any) { object["extension"] = strings.Repeat("x", 129) }),
			mutateLimits: func(limits *Limits) { limits.MaxJSONStringBytes = 128 },
		},
		"excessive document bytes": {
			document:     fromObject(func(object map[string]any) { object["extension"] = strings.Repeat("x", 600) }),
			mutateLimits: func(limits *Limits) { limits.MaxDiscoveryBytes = minimumDiscoveryBytes },
		},
		"missing issuer": {
			document: fromObject(func(object map[string]any) { delete(object, "issuer") }),
		},
		"null issuer": {
			document: fromObject(func(object map[string]any) { object["issuer"] = nil }),
		},
		"number issuer": {
			document: fromObject(func(object map[string]any) { object["issuer"] = 42 }),
		},
		"HTTP authorization endpoint": {
			document: fromObject(func(object map[string]any) { object["authorization_endpoint"] = "http://provider.example/authorize" }),
		},
		"token endpoint query": {
			document: fromObject(func(object map[string]any) { object["token_endpoint"] = testToken + "?secret=" + testHostileSentinel }),
		},
		"JWKS endpoint fragment": {
			document: fromObject(func(object map[string]any) { object["jwks_uri"] = testJWKS + "#fragment" }),
		},
		"UserInfo endpoint userinfo": {
			document: fromObject(func(object map[string]any) {
				object["userinfo_endpoint"] = "https://user:pass@provider.example/userinfo"
			}),
		},
		"revocation endpoint noncanonical host": {
			document: fromObject(func(object map[string]any) { object["revocation_endpoint"] = "https://Provider.Example/revoke" }),
		},
		"end-session endpoint path traversal": {
			document: fromObject(func(object map[string]any) { object["end_session_endpoint"] = "https://provider.example/../logout" }),
		},
		"response type omits code": {
			document: fromObject(func(object map[string]any) { object["response_types_supported"] = []string{"id_token"} }),
		},
		"duplicate response type": {
			document: fromObject(func(object map[string]any) {
				object["response_types_supported"] = []string{ResponseTypeCode, ResponseTypeCode}
			}),
		},
		"response mode omits query": {
			document: fromObject(func(object map[string]any) { object["response_modes_supported"] = []string{"fragment"} }),
		},
		"grant type omits authorization code": {
			document: fromObject(func(object map[string]any) { object["grant_types_supported"] = []string{"implicit"} }),
		},
		"challenge omits S256": {
			document: fromObject(func(object map[string]any) { object["code_challenge_methods_supported"] = []string{"plain"} }),
		},
		"token auth omits configured mode": {
			document: fromObject(func(object map[string]any) { object["token_endpoint_auth_methods_supported"] = []string{"none"} }),
		},
		"unsupported subject type": {
			document: fromObject(func(object map[string]any) { object["subject_types_supported"] = []string{"public", "sector"} }),
		},
		"advertised scopes omit openid": {
			document: fromObject(func(object map[string]any) { object["scopes_supported"] = []string{"profile"} }),
		},
		"no allowed signing algorithm": {
			document: fromObject(func(object map[string]any) { object["id_token_signing_alg_values_supported"] = []string{"none"} }),
		},
		"duplicate signing algorithm": {
			document: fromObject(func(object map[string]any) {
				object["id_token_signing_alg_values_supported"] = []string{string(SigningRS256), string(SigningRS256)}
			}),
		},
		"control in metadata value": {
			document: fromObject(func(object map[string]any) {
				object["response_types_supported"] = []string{ResponseTypeCode, "bad\nvalue"}
			}),
		},
		"long number token": {
			document: validWithRawMember(`"extension":11111111111111111111111111111111111111111111111111111111111111111`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			document := test.document(t)
			client, _ := newTrustTestClient(t, []federatedhttp.Result{
				successfulResult(federatedhttp.DocumentOIDCDiscovery, document),
			}, test.mutateLimits)
			_, err := client.FetchDiscovery(context.Background(), validDiscoveryRequest())
			want := test.want
			if want == nil {
				want = ErrDiscoveryRejected
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			if strings.Contains(err.Error(), testHostileSentinel) {
				t.Fatal("rejection leaked hostile document content")
			}
		})
	}
}

func TestBoundedJSONRejectsDuplicateEscapedNamesAtEveryDepth(t *testing.T) {
	limits := DefaultLimits()
	tests := [][]byte{
		[]byte(`{"name":1,"na\u006de":2}`),
		[]byte(`{"outer":{"name":1,"na\u006de":2}}`),
		[]byte(`{"outer":[{"name":1,"na\u006de":2}]}`),
	}
	for _, document := range tests {
		if err := validateBoundedJSONObject(document, len(document), limits); err == nil {
			t.Fatalf("accepted duplicate-member document %q", document)
		}
	}
}

func appendJSONObjectMember(t *testing.T, document []byte, member string) []byte {
	t.Helper()
	document = bytes.TrimSpace(document)
	if len(document) < 2 || document[len(document)-1] != '}' {
		t.Fatal("test fixture is not an object")
	}
	result := make([]byte, 0, len(document)+len(member)+1)
	result = append(result, document[:len(document)-1]...)
	result = append(result, ',')
	result = append(result, member...)
	result = append(result, '}')
	return result
}
