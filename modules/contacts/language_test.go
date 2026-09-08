package contacts

import "testing"

func TestContactLanguageMatchesCanonicalContract(t *testing.T) {
	for _, value := range []string{"it", "it-IT", "en-US", "zh-Hant", "zh-Hant-TW", "es-419"} {
		if !validLanguage(value) {
			t.Errorf("canonical language rejected: %s", value)
		}
	}
	for _, value := range []string{"", "it-it", "IT", "zh-hant-TW", "en-US-extra", "it_IT", "it-IT\n", "it-IT<script>"} {
		if validLanguage(value) {
			t.Errorf("noncanonical language accepted: %s", value)
		}
	}
}
