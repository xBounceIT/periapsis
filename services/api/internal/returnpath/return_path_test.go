package returnpath

import (
	"net/url"
	"strings"
	"testing"
)

func TestValidCanonicalReturnPaths(t *testing.T) {
	for _, value := range []string{
		"/", "/alerts", "/alerts?state=new", "/?auth=federated-mfa", "/alerts?",
		"/a%20b", "/caf%C3%A9", "/a%3Fb", "/a%23b", "/100%25",
		"/alerts?search=https%3A%2F%2Fexample.test%2Fa&label=caf%C3%A9",
		"/" + strings.Repeat("a", maximumBytes-1),
	} {
		t.Run(value, func(t *testing.T) {
			if !Valid(value) {
				t.Fatalf("rejected canonical local path %q", value)
			}
			base, _ := url.Parse("https://periapsis.example/")
			relative, err := url.Parse(value)
			if err != nil || base.ResolveReference(relative).Host != base.Host {
				t.Fatalf("accepted path changed authority: %q", value)
			}
		})
	}
}

func TestInvalidReturnPaths(t *testing.T) {
	for _, value := range []string{
		"", "alerts", "https://evil.example", "http://evil.example", "javascript:alert(1)",
		"//evil.example", "///evil.example", `/\evil.example`, `/a\b`,
		"/a//b", "/a/../b", "/a/./b", "/a/", "/a#fragment", "/a%2Fb", "/a/%2e%2e/b",
		"/%2Fevil.example", "/%2fevil.example", "/%5Cevil.example", "/%5cevil.example",
		"/%00evil.example", "/%09evil.example", "/%0Aevil.example", "/%0Devil.example",
		"/%7Fevil.example", "/%C2%85evil.example", "/%FF", "/%ZZ", "/%",
		"/a\r\nb", "/\tevil.example", "/a\u0085b", "/\xff", " /alerts", "/alerts ",
		"/" + strings.Repeat("a", maximumBytes),
	} {
		t.Run(value, func(t *testing.T) {
			if Valid(value) {
				t.Fatalf("accepted invalid return path %q", value)
			}
		})
	}
}
