package platformsamladapter

import (
	"strings"
	"testing"
)

func TestCanonicalProviderKeyMatchesAdminContract(t *testing.T) {
	for _, valid := range []string{"saml", "workforce_saml", "a-b", "a_1", "a" + strings.Repeat("z", 63)} {
		if !providerKeyPattern.MatchString(valid) {
			t.Errorf("canonical provider key %q was rejected", valid)
		}
	}
	for _, invalid := range []string{
		"", "a", "ab", "1ab", "_ab", "-ab", "Workforce_saml", "a.b", "a/b", "a" + strings.Repeat("z", 64),
	} {
		if providerKeyPattern.MatchString(invalid) {
			t.Errorf("non-canonical provider key %q was accepted", invalid)
		}
	}
}
