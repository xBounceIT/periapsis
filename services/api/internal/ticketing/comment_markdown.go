package ticketing

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"net/url"
	"strings"
	"unicode"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	nethtml "golang.org/x/net/html"
)

const maximumRenderedCommentBytes = 100_000

var (
	commentMarkdown   = goldmark.New()
	commentHTMLPolicy = newCommentHTMLPolicy()
	commentTextPolicy = bluemonday.StrictPolicy()
)

type commentMarkdownConverter func(source []byte, destination io.Writer) error

// RenderCommentMarkdown converts a validated comment body to deterministic,
// allowlisted HTML. It is the canonical renderer for writes and previews.
func RenderCommentMarkdown(value string) (string, error) {
	return renderCommentMarkdown(value, func(source []byte, destination io.Writer) error {
		return commentMarkdown.Convert(source, destination)
	})
}

func renderCommentMarkdown(value string, convert commentMarkdownConverter) (string, error) {
	if !validCommentMarkdownSource(value) {
		return "", ErrInvalidInput
	}
	if convert == nil {
		return "", fmt.Errorf("%w: comment Markdown renderer is not configured", ErrUnavailable)
	}

	var rendered bytes.Buffer
	if err := convert([]byte(value), &rendered); err != nil {
		return "", fmt.Errorf("%w: render comment Markdown", ErrUnavailable)
	}

	sanitized := bytes.TrimSpace(commentHTMLPolicy.SanitizeBytes(rendered.Bytes()))
	if len(sanitized) > maximumRenderedCommentBytes {
		return "", ErrInvalidInput
	}
	if !validRenderedCommentCharacters(sanitized) || !validRenderedCommentLinks(sanitized) ||
		!hasRenderedCommentContent(sanitized) {
		return "", ErrInvalidInput
	}
	return string(sanitized), nil
}

func validRenderedCommentHTML(value string) bool {
	if !validText(value, maximumRenderedCommentBytes, true) {
		return false
	}
	rendered := []byte(value)
	sanitized := bytes.TrimSpace(commentHTMLPolicy.SanitizeBytes(rendered))
	return bytes.Equal(rendered, sanitized) && validRenderedCommentCharacters(sanitized) &&
		validRenderedCommentLinks(sanitized) &&
		hasRenderedCommentContent(sanitized)
}

func validRenderedCommentCharacters(value []byte) bool {
	for _, character := range html.UnescapeString(string(value)) {
		if character != '\n' && character != '\t' && unicode.IsControl(character) ||
			commentDirectionalControl(character) {
			return false
		}
	}
	return true
}

func validRenderedCommentLinks(value []byte) bool {
	tokenizer := nethtml.NewTokenizer(bytes.NewReader(value))
	openElements := make([]string, 0, 8)
	for {
		switch tokenizer.Next() {
		case nethtml.ErrorToken:
			return tokenizer.Err() == io.EOF && len(openElements) == 0
		case nethtml.SelfClosingTagToken, nethtml.CommentToken, nethtml.DoctypeToken:
			return false
		case nethtml.StartTagToken:
			token := tokenizer.Token()
			if token.Data == "br" || token.Data == "hr" {
				if len(token.Attr) != 0 {
					return false
				}
				continue
			}
			if !validRenderedCommentContainer(token.Data) {
				return false
			}
			openElements = append(openElements, token.Data)
			if token.Data != "a" {
				if len(token.Attr) != 0 {
					return false
				}
				continue
			}
			var href, rel string
			hasHref, hasTitle, hasRel := false, false, false
			attributeKeys := make([]string, 0, len(token.Attr))
			for _, attribute := range token.Attr {
				attributeKeys = append(attributeKeys, attribute.Key)
				switch attribute.Key {
				case "href":
					if hasHref {
						return false
					}
					href, hasHref = attribute.Val, true
				case "title":
					if hasTitle {
						return false
					}
					hasTitle = true
				case "rel":
					if hasRel {
						return false
					}
					rel, hasRel = attribute.Val, true
				default:
					return false
				}
			}
			if !hasHref || !validRenderedCommentLinkAttributeOrder(attributeKeys, hasTitle, hasRel) ||
				!validRenderedCommentLinkTarget(href, rel) {
				return false
			}
		case nethtml.EndTagToken:
			token := tokenizer.Token()
			if !validRenderedCommentContainer(token.Data) || len(token.Attr) != 0 ||
				len(openElements) == 0 || openElements[len(openElements)-1] != token.Data {
				return false
			}
			openElements = openElements[:len(openElements)-1]
		}
	}
}

func validRenderedCommentContainer(name string) bool {
	switch name {
	case "p", "strong", "em", "ul", "ol", "li", "blockquote", "pre", "code",
		"h1", "h2", "h3", "h4", "h5", "h6", "a":
		return true
	default:
		return false
	}
}

func validRenderedCommentLinkAttributeOrder(keys []string, hasTitle, hasRel bool) bool {
	expectedLength := 1
	if hasTitle {
		expectedLength++
	}
	if hasRel {
		expectedLength++
	}
	if len(keys) != expectedLength || keys[0] != "href" {
		return false
	}
	index := 1
	if hasTitle {
		if keys[index] != "title" {
			return false
		}
		index++
	}
	return !hasRel || keys[index] == "rel"
}

func validRenderedCommentLinkTarget(href, rel string) bool {
	// Network-path references are not a stable local-link representation:
	// browsers can interpret two or more leading slashes as an external
	// authority while net/url and sanitizers disagree for the three-slash case.
	if href == "" || strings.HasPrefix(href, "//") || strings.ContainsAny(href, "\t\r\n\\") {
		return false
	}
	parsed, err := url.Parse(href)
	if err != nil {
		return false
	}
	if parsed.IsAbs() {
		return (parsed.Scheme == "http" || parsed.Scheme == "https") &&
			validRenderedCommentHTTPAuthority(parsed) &&
			strings.HasPrefix(href, parsed.Scheme+"://") && rel == "nofollow noreferrer"
	}
	return parsed.Scheme == "" && parsed.Host == "" && rel == ""
}

func validRenderedCommentHTTPAuthority(parsed *url.URL) bool {
	if parsed == nil || parsed.User != nil || parsed.Host == "" ||
		strings.ContainsAny(parsed.Host, "[]@") {
		return false
	}
	host, port := parsed.Hostname(), parsed.Port()
	if host == "" || parsed.Host != host && (port == "" || parsed.Host != host+":"+port) {
		return false
	}
	for _, character := range host {
		if character > unicode.MaxASCII || !unicode.IsLetter(character) && !unicode.IsDigit(character) &&
			!strings.ContainsRune("._~-", character) {
			return false
		}
	}
	return true
}

func hasRenderedCommentContent(value []byte) bool {
	plainText := commentTextPolicy.SanitizeBytes(value)
	return len(bytes.TrimSpace(plainText)) != 0 || bytes.Contains(value, []byte("<hr>"))
}

func newCommentHTMLPolicy() *bluemonday.Policy {
	policy := bluemonday.NewPolicy()
	policy.AllowElements(
		"p", "br", "strong", "em", "ul", "ol", "li", "blockquote",
		"pre", "code", "h1", "h2", "h3", "h4", "h5", "h6", "hr",
	)
	policy.AllowAttrs("href", "title").OnElements("a")
	policy.AllowURLSchemes("http", "https")
	policy.AllowRelativeURLs(true)
	policy.RequireNoFollowOnFullyQualifiedLinks(true)
	policy.RequireNoReferrerOnFullyQualifiedLinks(true)
	return policy
}
