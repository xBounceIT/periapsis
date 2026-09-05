package federatedsaml

import (
	"strings"
	"testing"
)

func TestBoundedXMLParserRejectsStructuralCorpus(t *testing.T) {
	limits := DefaultLimits()
	deep := strings.Repeat(`<saml:A xmlns:saml="`+samlAssertionNamespace+`">`, limits.MaxXMLDepth+1) +
		strings.Repeat(`</saml:A>`, limits.MaxXMLDepth+1)
	tests := map[string]string{
		"excessive depth":              deep,
		"duplicate expanded attribute": `<saml:A xmlns:saml="` + samlAssertionNamespace + `" ID="_one" ID="_two"/>`,
		"case-confusable ID":           `<saml:A xmlns:saml="` + samlAssertionNamespace + `" Id="_one"/>`,
		"colon ID":                     `<saml:A xmlns:saml="` + samlAssertionNamespace + `" ID="prefix:value"/>`,
		"external namespace":           `<evil:A xmlns:evil="urn:attacker:SECRET"/>`,
		"processing instruction":       `<?target SECRET?><saml:A xmlns:saml="` + samlAssertionNamespace + `"/>`,
		"comment":                      `<saml:A xmlns:saml="` + samlAssertionNamespace + `"><!-- SECRET --></saml:A>`,
		"DTD":                          `<!DOCTYPE A SYSTEM "file:///SECRET"><saml:A xmlns:saml="` + samlAssertionNamespace + `"/>`,
		"multiple roots":               `<saml:A xmlns:saml="` + samlAssertionNamespace + `"/><saml:B xmlns:saml="` + samlAssertionNamespace + `"/>`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBoundedXML([]byte(document), DefaultLimits().MaxDecodedResponseBytes, limits); err == nil {
				t.Fatal("parseBoundedXML() unexpectedly succeeded")
			} else if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error leaked hostile input: %v", err)
			}
		})
	}
}

func TestBoundedXMLParserRejectsNodeAttributeAndTextLimits(t *testing.T) {
	base := DefaultLimits()
	tests := []struct {
		document string
		limits   Limits
	}{
		{document: `<saml:A xmlns:saml="` + samlAssertionNamespace + `"><saml:B/><saml:C/></saml:A>`, limits: withXMLLimits(base, 2, base.MaxXMLAttributes, base.MaxXMLTextBytes)},
		{document: `<saml:A xmlns:saml="` + samlAssertionNamespace + `" First="1" Second="2"/>`, limits: withXMLLimits(base, base.MaxXMLNodes, 2, base.MaxXMLTextBytes)},
		{document: `<saml:A xmlns:saml="` + samlAssertionNamespace + `">abcd</saml:A>`, limits: withXMLLimits(base, base.MaxXMLNodes, base.MaxXMLAttributes, 3)},
	}
	for index, test := range tests {
		if _, err := parseBoundedXML([]byte(test.document), DefaultLimits().MaxDecodedResponseBytes, test.limits); err == nil {
			t.Fatalf("case %d unexpectedly succeeded", index)
		}
	}
}

func FuzzBoundedXMLParserNeverPanics(f *testing.F) {
	for _, document := range [][]byte{
		[]byte(`<saml:Assertion xmlns:saml="` + samlAssertionNamespace + `" ID="_one"/>`),
		[]byte(`<saml:Assertion xmlns:saml="` + samlAssertionNamespace + `" ID="_one"><saml:Assertion ID="_one"/></saml:Assertion>`),
		[]byte(`<!DOCTYPE A SYSTEM "file:///hostile"><saml:A xmlns:saml="` + samlAssertionNamespace + `"/>`),
		{0xff, 0xfe, '<', 'A', '/', '>'},
	} {
		f.Add(document)
	}
	limits := DefaultLimits()
	f.Fuzz(func(t *testing.T, document []byte) {
		_, _ = parseBoundedXML(document, limits.MaxDecodedResponseBytes, limits)
	})
}

func withXMLLimits(base Limits, nodes, attributes, text int) Limits {
	base.MaxXMLNodes = nodes
	base.MaxXMLAttributes = attributes
	base.MaxXMLTextBytes = text
	return base
}
