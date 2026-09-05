package ticketing

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestRenderCommentMarkdownRendersSupportedMarkdown(t *testing.T) {
	t.Parallel()

	source := strings.Join([]string{
		"# Heading",
		"",
		"**strong** and *emphasis* with `inline code`.",
		"",
		"- first",
		"- second",
		"",
		"```go",
		`fmt.Println("safe")`,
		"```",
		"",
		"[relative](/tickets/123) and [external](https://example.com/path?q=1).",
	}, "\n")

	got, err := RenderCommentMarkdown(source)
	if err != nil {
		t.Fatalf("RenderCommentMarkdown() error = %v", err)
	}
	for _, want := range []string{
		"<h1>Heading</h1>",
		"<strong>strong</strong>",
		"<em>emphasis</em>",
		"<code>inline code</code>",
		"<ul>",
		"<li>first</li>",
		"<pre><code>",
		`href="/tickets/123"`,
		`href="https://example.com/path?q=1"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderCommentMarkdown() output missing %q:\n%s", want, got)
		}
	}
	if len(got) > maximumRenderedCommentBytes {
		t.Fatalf("RenderCommentMarkdown() bytes = %d, maximum = %d", len(got), maximumRenderedCommentBytes)
	}
	if strings.TrimSpace(got) != got {
		t.Fatalf("RenderCommentMarkdown() retained surrounding whitespace: %q", got)
	}
	if !validRenderedCommentHTML(got) {
		t.Fatalf("RenderCommentMarkdown() output fails stored comment validation: %q", got)
	}
}

func TestRenderCommentMarkdownRejectsInvalidSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
	}{
		{name: "empty"},
		{name: "leading whitespace", source: " comment"},
		{name: "trailing whitespace", source: "comment "},
		{name: "raw HTML", source: `<strong onclick="alert(1)">unsafe</strong>`},
		{name: "script", source: `<script>alert(1)</script>`},
		{name: "style", source: `<style>body { display: none }</style>`},
		{name: "form", source: `<form action="https://example.com"><input></form>`},
		{name: "iframe", source: `<iframe src="https://example.com"></iframe>`},
		{name: "control", source: "comment\x00body"},
		{name: "directional control", source: "comment\u202ebody"},
		{name: "encoded directional control", source: "comment &#x202e; body"},
		{name: "invalid UTF-8", source: string([]byte{0xff, 'x'})},
		{name: "source over bound", source: strings.Repeat("a", maximumCommentCharacters+1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := RenderCommentMarkdown(test.source)
			if !errors.Is(err, ErrInvalidInput) || got != "" {
				t.Fatalf("RenderCommentMarkdown() = %q, %v; want empty ErrInvalidInput", got, err)
			}
		})
	}
}

func TestRenderCommentMarkdownAllowsEncodedDirectionalIndicatorAsCode(t *testing.T) {
	t.Parallel()

	for _, source := range []string{"Observed `&#x202e;` in the payload.", "```text\n&#x202e;\n```"} {
		got, err := RenderCommentMarkdown(source)
		if err != nil || !strings.Contains(got, "&amp;#x202e;") {
			t.Fatalf("RenderCommentMarkdown(%q) = %q, %v; want literal forensic indicator", source, got, err)
		}
	}
}

func TestRenderCommentMarkdownSanitizesLinksAndImages(t *testing.T) {
	t.Parallel()

	source := strings.Join([]string{
		"[javascript](javascript:alert(1))",
		"[data](data:text/html;base64,PHNjcmlwdD4=)",
		"[file](file:///etc/passwd)",
		"[mail](mailto:test@example.com)",
		"![tracking pixel](https://example.com/tracker.png)",
	}, "\n\n")
	got, err := RenderCommentMarkdown(source)
	if err != nil {
		t.Fatalf("RenderCommentMarkdown() error = %v", err)
	}

	lower := strings.ToLower(got)
	for _, forbidden := range []string{
		"javascript:", "data:", "file:", "mailto:", "<img", "src=", "<script", "<style",
		"<form", "<iframe", "onclick", "onerror",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("RenderCommentMarkdown() retained forbidden content %q:\n%s", forbidden, got)
		}
	}
}

func TestRenderCommentMarkdownRejectsAmbiguousOrMalformedLinkTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"//example.invalid/path",
		"///example.invalid/path",
		"////example.invalid/path",
		"https:relative-looking",
	} {
		t.Run(target, func(t *testing.T) {
			source := "[destination](" + target + ")"
			if rendered, err := RenderCommentMarkdown(source); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("RenderCommentMarkdown(%q) = %q, %v; want ErrInvalidInput", source, rendered, err)
			}
		})
	}
}

func TestRenderCommentMarkdownCanonicalizesOrRemovesMalformedLinkTargets(t *testing.T) {
	t.Parallel()

	invalidHost, err := RenderCommentMarkdown("[destination](https://[bad-ipv6)")
	if err != nil || invalidHost != "<p>destination</p>" {
		t.Fatalf("invalid host result = %q, %v; want safe plain text", invalidHost, err)
	}
	invalidEscape, err := RenderCommentMarkdown("[destination](https://example.invalid/%zz)")
	if err != nil || !strings.Contains(invalidEscape, `href="https://example.invalid/%25zz"`) ||
		!validRenderedCommentHTML(invalidEscape) {
		t.Fatalf("invalid escape result = %q, %v; want canonical escaped URL", invalidEscape, err)
	}
	for source, target := range map[string]string{
		`[destination](\\example.invalid\path)`: `%5Cexample.invalid%5Cpath`,
		`[destination](/\example.invalid/path)`: `/%5Cexample.invalid/path`,
		`[destination](é/{value})`:              `%C3%A9/%7Bvalue%7D`,
	} {
		rendered, renderErr := RenderCommentMarkdown(source)
		if renderErr != nil || !strings.Contains(rendered, `href="`+target+`"`) ||
			!validRenderedCommentHTML(rendered) {
			t.Fatalf("backslash target result = %q, %v; want canonical escaped URL", rendered, renderErr)
		}
	}
}

func TestValidRenderedCommentHTMLUsesCanonicalLinkSubset(t *testing.T) {
	t.Parallel()

	accepted := []string{
		`<p><a href="https://example.invalid/path" rel="nofollow noreferrer">external</a></p>`,
		`<p><a href="https://example.invalid:8443/path" rel="nofollow noreferrer">external port</a></p>`,
		`<p><a href="/tickets/1">absolute path</a></p>`,
		`<p><a href="../tickets/1">relative path</a></p>`,
		`<p><a href="?view=compact&amp;page=2">query</a></p>`,
		`<p><a href="#history">fragment</a></p>`,
		`<p><a href="%C3%A9/%7Bvalue%7D">escaped Unicode and braces</a></p>`,
	}
	for _, value := range accepted {
		if !validRenderedCommentHTML(value) {
			t.Errorf("validRenderedCommentHTML(%q) = false, want true", value)
		}
	}

	rejected := []string{
		`<p><a href="">empty</a></p>`,
		`<p><a href="//example.invalid" rel="nofollow noreferrer">network path</a></p>`,
		`<p><a href="///example.invalid">ambiguous network path</a></p>`,
		`<p><a href="\\example.invalid\path">backslash network path</a></p>`,
		`<p><a href="/\example.invalid/path">mixed network path</a></p>`,
		`<p><a href="https:relative-looking">opaque HTTPS</a></p>`,
		`<p><a href="https://example.invalid:" rel="nofollow noreferrer">empty port</a></p>`,
		`<p><a href="https://user@example.invalid/path" rel="nofollow noreferrer">userinfo</a></p>`,
		`<p><a href="https://täst.invalid/path" rel="nofollow noreferrer">unicode host</a></p>`,
		`<p><a href="https://[::1]/path" rel="nofollow noreferrer">IPv6 host</a></p>`,
		`<p><a href="https://example.invalid/%zz" rel="nofollow noreferrer">bad escape</a></p>`,
		`<p><a href="é">raw Unicode path</a></p>`,
		`<p><a href="/{value}">raw URL braces</a></p>`,
		`<p><a href="https://[bad-ipv6" rel="nofollow noreferrer">bad host</a></p>`,
		`<p><a href="/tickets/1" rel="nofollow noreferrer">relative rel</a></p>`,
		`<p><a href="https://example.invalid">missing rel</a></p>`,
		`<p><a title="ticket" href="/tickets/1">reordered attributes</a></p>`,
		`<p><a href="https://example.invalid" rel="nofollow noreferrer" title="ticket">reordered rel</a></p>`,
		`<p><a href="/tickets/1" title="one" title="two">duplicate title</a></p>`,
	}
	for _, value := range rejected {
		if validRenderedCommentHTML(value) {
			t.Errorf("validRenderedCommentHTML(%q) = true, want false", value)
		}
	}
}

func TestValidCommentAllowsSanitizedForensicIndicators(t *testing.T) {
	fixture := newServiceFixture(t)
	tests := []struct {
		name   string
		source string
	}{
		{name: "javascript prose", source: "Observed the literal javascript: scheme in a quarantined sample."},
		{name: "event handler inline code", source: "The attribute `onload=` appeared in the captured payload."},
		{name: "script tag inline code", source: "The payload contained `<script>alert(1)</script>` as evidence."},
		{name: "escaped script tag", source: "The payload began with &lt;script before truncation."},
		{name: "forensic code block", source: strings.Join([]string{
			"```text", "javascript:alert(1)", "onload=collectEvidence()", "<script>alert(1)</script>", "```",
		}, "\n")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rendered, err := RenderCommentMarkdown(test.source)
			if err != nil {
				t.Fatalf("RenderCommentMarkdown() error = %v", err)
			}
			comment := Comment{
				ID: mustUUIDv7(t), TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID,
				ResourceKind: kernel.AggregateAlert, Visibility: kernel.CommentPrivate,
				BodyMarkdown: test.source, BodyHTML: rendered,
				Author: CommentAuthor{
					MembershipID: fixture.membershipUUID, DisplayName: "DFIR Operator", Audience: CommentAudienceOperator,
				},
				Origin: CommentOriginAPI, Revision: 1, CreatedAt: fixture.record.CreatedAt,
				UpdatedAt:     fixture.record.CreatedAt,
				EditableUntil: fixture.record.CreatedAt.Add(commentEditWindowSeconds * time.Second),
			}
			membership, _ := entityID(fixture.membershipUUID)
			if !validRenderedCommentHTML(rendered) || !validComment(
				comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator,
				LiveAccess{MembershipID: membership}, fixture.record.CreatedAt,
			) {
				t.Fatalf("canonical forensic comment was rejected: %q", rendered)
			}
		})
	}
}

func TestValidRenderedCommentHTMLRejectsUnsafeOrNonCanonicalHTML(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`<script>alert(1)</script>`,
		`<style>body { display: none }</style>`,
		`<form action="/steal"><input></form>`,
		`<iframe src="https://example.com"></iframe>`,
		`<img src="https://example.com/tracker.png" onerror="alert(1)">`,
		`<p onload="alert(1)">forensic note</p>`,
		`<a href="javascript:alert(1)">forensic note</a>`,
		`<p>&#9;</p>`,
		`<p>&#10;</p>`,
		`<p>&#160</p>`,
		`<p>&#xA0</p>`,
		`<p>&Tab;</p>`,
		`<p>&NewLine;</p>`,
		`<p>&nbsp</p>`,
		`<p>&copy;</p>`,
		`<p>&quot;</p>`,
		`<p>&apos;</p>`,
		`<p>&#169;</p>`,
		`<p>&#x3c;</p>`,
		`<p>raw & ampersand</p>`,
		`<p>raw " quote</p>`,
		`<p>raw ' apostrophe</p>`,
		`<p>x<br/></p>`,
		`<p>x<hr/></p>`,
		`<p>x<strong/></p>`,
		`<p><a href="/tickets/1"/>x</p>`,
		`<p><strong>x</p></strong>`,
		`<p><em>x</strong></p>`,
		`<p>x</p></p>`,
		`<p><br></br></p>`,
		`<!-- comment --><p>x</p>`,
		`<!doctype html><p>x</p>`,
		"<p>forensic note</p>\n",
	} {
		if validRenderedCommentHTML(value) {
			t.Errorf("validRenderedCommentHTML(%q) = true, want false", value)
		}
	}
}

func TestValidRenderedCommentHTMLAcceptsLegacyEscapedOutput(t *testing.T) {
	t.Parallel()

	legacy := "Evidence &lt;tag&gt; &amp; &#34;quoted&#34; text.<br>\nSecond line"
	if !validRenderedCommentHTML(legacy) {
		t.Fatalf("validRenderedCommentHTML(%q) = false, want legacy compatibility", legacy)
	}
}

func TestRenderCommentMarkdownRejectsContentRemovedBySanitizer(t *testing.T) {
	t.Parallel()

	for _, source := range []string{
		"![tracking pixel](https://example.com/tracker.png)",
		"- ![tracking pixel](https://example.com/tracker.png)",
	} {
		got, err := RenderCommentMarkdown(source)
		if !errors.Is(err, ErrInvalidInput) || got != "" {
			t.Fatalf("RenderCommentMarkdown(%q) = %q, %v; want empty ErrInvalidInput", source, got, err)
		}
	}
}

func TestRenderCommentMarkdownAllowsThematicBreak(t *testing.T) {
	t.Parallel()

	got, err := RenderCommentMarkdown("---")
	if err != nil || !strings.Contains(got, "<hr>") {
		t.Fatalf("RenderCommentMarkdown(thematic break) = %q, %v; want safe hr", got, err)
	}
}

func TestRenderCommentMarkdownPreservesUnicodeAndIsDeterministic(t *testing.T) {
	t.Parallel()

	source := "**Risposta:** caffè ☕ — 日本語 — العربية"
	first, err := RenderCommentMarkdown(source)
	if err != nil {
		t.Fatalf("RenderCommentMarkdown() error = %v", err)
	}
	if !utf8.ValidString(first) {
		t.Fatalf("RenderCommentMarkdown() returned invalid UTF-8: %q", first)
	}
	for _, want := range []string{"caffè", "☕", "日本語", "العربية"} {
		if !strings.Contains(first, want) {
			t.Errorf("RenderCommentMarkdown() output missing %q: %s", want, first)
		}
	}
	for iteration := 0; iteration < 20; iteration++ {
		got, renderErr := RenderCommentMarkdown(source)
		if renderErr != nil || got != first {
			t.Fatalf("iteration %d = %q, %v; want deterministic %q", iteration, got, renderErr, first)
		}
	}
}

func TestRenderCommentMarkdownEnforcesRenderedBound(t *testing.T) {
	t.Parallel()

	if got, err := RenderCommentMarkdown(strings.Repeat("a", maximumCommentCharacters)); err != nil {
		t.Fatalf("RenderCommentMarkdown(maximum source) error = %v", err)
	} else if len(got) > maximumRenderedCommentBytes {
		t.Fatalf("RenderCommentMarkdown(maximum source) bytes = %d", len(got))
	}

	got, err := RenderCommentMarkdown(strings.Repeat("&", maximumCommentCharacters))
	if !errors.Is(err, ErrInvalidInput) || got != "" {
		t.Fatalf("RenderCommentMarkdown(expanded output) = %q, %v; want empty ErrInvalidInput", got, err)
	}
}

func TestRenderCommentMarkdownMapsRendererFailure(t *testing.T) {
	t.Parallel()

	failure := errors.New("renderer failed")
	got, err := renderCommentMarkdown("valid Markdown", func([]byte, io.Writer) error {
		return failure
	})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, failure) || got != "" {
		t.Fatalf("renderCommentMarkdown() = %q, %v; want redacted ErrUnavailable", got, err)
	}
}
