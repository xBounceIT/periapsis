package dfir

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecideFileTypeMatrix(t *testing.T) {
	tests := []struct {
		name              string
		declared          string
		detected          string
		prefix            []byte
		wantVerdict       FileTypeVerdict
		wantClass         FileTypeClass
		wantReason        FileTypeReason
		wantCanonicalDecl string
		wantCanonicalDet  string
	}{
		{
			name:     "matching generic binary",
			declared: "Application/Octet-Stream", detected: "application/octet-stream",
			wantVerdict: FileTypeVerdictAllow, wantClass: FileTypeClassGenericBinary,
			wantReason:        FileTypeReasonConsistentBinary,
			wantCanonicalDecl: "application/octet-stream", wantCanonicalDet: "application/octet-stream",
		},
		{
			name:     "case and parameters are canonicalized",
			declared: "Text/Plain; Charset=UTF-8; Format=flowed", detected: "text/plain; format=flowed; charset=utf-8",
			wantVerdict: FileTypeVerdictAllow, wantClass: FileTypeClassPassive,
			wantReason:        FileTypeReasonConsistentPassive,
			wantCanonicalDecl: "text/plain; charset=utf-8; format=flowed",
			wantCanonicalDet:  "text/plain; charset=utf-8; format=flowed",
		},
		{
			name:     "parameters do not disguise matching essence",
			declared: "image/png; name=evidence.png", detected: "IMAGE/PNG", prefix: pngContentPrefix(),
			wantVerdict: FileTypeVerdictAllow, wantClass: FileTypeClassPassive,
			wantReason:        FileTypeReasonConsistentPassive,
			wantCanonicalDecl: "image/png; name=evidence.png", wantCanonicalDet: "image/png",
		},
		{
			name:     "two recognized passive essences mismatch",
			declared: "image/png", detected: "image/jpeg",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassSuspiciousMismatch,
			wantReason:        FileTypeReasonMIMEMismatch,
			wantCanonicalDecl: "image/png", wantCanonicalDet: "image/jpeg",
		},
		{
			name:     "generic detector does not excuse a concrete declaration",
			declared: "application/zip", detected: "application/octet-stream",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassSuspiciousMismatch,
			wantReason:        FileTypeReasonMIMEMismatch,
			wantCanonicalDecl: "application/zip", wantCanonicalDet: "application/octet-stream",
		},
		{
			name: "html", declared: "text/html", detected: "text/html",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassActiveContent,
			wantReason:        FileTypeReasonActiveContent,
			wantCanonicalDecl: "text/html", wantCanonicalDet: "text/html",
		},
		{
			name: "xhtml", declared: "application/xhtml+xml", detected: "application/xhtml+xml",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassActiveContent,
			wantReason:        FileTypeReasonActiveContent,
			wantCanonicalDecl: "application/xhtml+xml", wantCanonicalDet: "application/xhtml+xml",
		},
		{
			name: "svg", declared: "image/svg+xml", detected: "image/svg+xml",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassActiveContent,
			wantReason:        FileTypeReasonActiveContent,
			wantCanonicalDecl: "image/svg+xml", wantCanonicalDet: "image/svg+xml",
		},
		{
			name: "xml", declared: "application/xml", detected: "application/xml",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassActiveContent,
			wantReason:        FileTypeReasonActiveContent,
			wantCanonicalDecl: "application/xml", wantCanonicalDet: "application/xml",
		},
		{
			name: "text xml", declared: "text/xml", detected: "text/xml",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassActiveContent,
			wantReason:        FileTypeReasonActiveContent,
			wantCanonicalDecl: "text/xml", wantCanonicalDet: "text/xml",
		},
		{
			name: "vendor xml", declared: "application/vnd.example+xml", detected: "application/vnd.example+xml",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassActiveContent,
			wantReason:        FileTypeReasonActiveContent,
			wantCanonicalDecl: "application/vnd.example+xml", wantCanonicalDet: "application/vnd.example+xml",
		},
		{
			name: "pe", declared: "application/octet-stream", detected: "application/vnd.microsoft.portable-executable",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassExecutable,
			wantReason:        FileTypeReasonExecutable,
			wantCanonicalDecl: "application/octet-stream", wantCanonicalDet: "application/vnd.microsoft.portable-executable",
		},
		{
			name: "elf", declared: "application/x-elf", detected: "application/x-elf",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassExecutable,
			wantReason:        FileTypeReasonExecutable,
			wantCanonicalDecl: "application/x-elf", wantCanonicalDet: "application/x-elf",
		},
		{
			name: "script", declared: "text/plain", detected: "text/x-shellscript",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassScript,
			wantReason:        FileTypeReasonScript,
			wantCanonicalDecl: "text/plain", wantCanonicalDet: "text/x-shellscript",
		},
		{
			name: "detected unsafe class has attribution priority", declared: "text/html", detected: "application/x-elf",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassExecutable,
			wantReason:        FileTypeReasonExecutable,
			wantCanonicalDecl: "text/html", wantCanonicalDet: "application/x-elf",
		},
		{
			name: "unknown matching type", declared: "application/x-periapsis-unknown", detected: "application/x-periapsis-unknown",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassUnknown,
			wantReason:        FileTypeReasonUnknownMIME,
			wantCanonicalDecl: "application/x-periapsis-unknown", wantCanonicalDet: "application/x-periapsis-unknown",
		},
		{
			name: "unknown structured suffix remains denied", declared: "application/vnd.periapsis+json", detected: "application/vnd.periapsis+json",
			wantVerdict: FileTypeVerdictReject, wantClass: FileTypeClassUnknown,
			wantReason:        FileTypeReasonUnknownMIME,
			wantCanonicalDecl: "application/vnd.periapsis+json", wantCanonicalDet: "application/vnd.periapsis+json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := test.prefix
			if prefix == nil {
				prefix = []byte("bounded fixture content")
			}
			decision := DecideFileType(FileTypeInput{
				ContentPrefix: prefix,
				DeclaredMIME:  test.declared,
				DetectedMIME:  test.detected,
			})
			if got := decision.Verdict(); got != test.wantVerdict {
				t.Fatalf("Verdict() = %q, want %q", got, test.wantVerdict)
			}
			if got := decision.Class(); got != test.wantClass {
				t.Errorf("Class() = %q, want %q", got, test.wantClass)
			}
			if got := decision.Reason(); got != test.wantReason {
				t.Errorf("Reason() = %q, want %q", got, test.wantReason)
			}
			if got := decision.Allowed(); got != (test.wantVerdict == FileTypeVerdictAllow) {
				t.Errorf("Allowed() = %t", got)
			}
			if got := decision.CanonicalDeclaredMIME(); got != test.wantCanonicalDecl {
				t.Errorf("CanonicalDeclaredMIME() = %q, want %q", got, test.wantCanonicalDecl)
			}
			if got := decision.CanonicalDetectedMIME(); got != test.wantCanonicalDet {
				t.Errorf("CanonicalDetectedMIME() = %q, want %q", got, test.wantCanonicalDet)
			}
		})
	}
}

func TestDecideFileTypeContentPrefixMatrix(t *testing.T) {
	oversized := make([]byte, MaximumFileTypeContentPrefixBytes+1)
	maximumSized := make([]byte, MaximumFileTypeContentPrefixBytes)
	tests := []struct {
		name       string
		declared   string
		detected   string
		prefix     []byte
		wantAllow  bool
		wantClass  FileTypeClass
		wantReason FileTypeReason
	}{
		{
			name: "generic binary remains admissible", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: []byte{0x00, 0x01, 0x02, 0x03},
			wantAllow: true, wantClass: FileTypeClassGenericBinary, wantReason: FileTypeReasonConsistentBinary,
		},
		{
			name: "maximum bounded prefix remains admissible", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: maximumSized,
			wantAllow: true, wantClass: FileTypeClassGenericBinary, wantReason: FileTypeReasonConsistentBinary,
		},
		{
			name: "matching png signature", declared: "image/png", detected: "image/png",
			prefix: pngContentPrefix(), wantAllow: true,
			wantClass: FileTypeClassPassive, wantReason: FileTypeReasonConsistentPassive,
		},
		{
			name: "png signature cannot be disguised as octet stream", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: pngContentPrefix(),
			wantClass: FileTypeClassSuspiciousMismatch, wantReason: FileTypeReasonContentMismatch,
		},
		{
			name: "claimed png requires its signature", declared: "image/png", detected: "image/png",
			prefix:    []byte("not a png"),
			wantClass: FileTypeClassSuspiciousMismatch, wantReason: FileTypeReasonContentMismatch,
		},
		{
			name: "html hidden as plain text", declared: "text/plain", detected: "text/plain",
			prefix:    []byte("<!doctype html><html></html>"),
			wantClass: FileTypeClassActiveContent, wantReason: FileTypeReasonActiveContent,
		},
		{
			name: "comment prefixed svg hidden as plain text", declared: "text/plain", detected: "text/plain",
			prefix:    []byte("<!-- benign-looking -->\n<svg></svg>"),
			wantClass: FileTypeClassActiveContent, wantReason: FileTypeReasonActiveContent,
		},
		{
			name: "xml fragment hidden as octet stream", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: []byte("<evidence><item/></evidence>"),
			wantClass: FileTypeClassActiveContent, wantReason: FileTypeReasonActiveContent,
		},
		{
			name: "utf16 html hidden as octet stream", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: utf16LEContentPrefix("<html></html>"),
			wantClass: FileTypeClassActiveContent, wantReason: FileTypeReasonActiveContent,
		},
		{
			name: "pe hidden as octet stream", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: peContentPrefix(),
			wantClass: FileTypeClassExecutable, wantReason: FileTypeReasonExecutable,
		},
		{
			name: "elf hidden as octet stream", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01},
			wantClass: FileTypeClassExecutable, wantReason: FileTypeReasonExecutable,
		},
		{
			name: "shebang hidden as plain text", declared: "text/plain", detected: "text/plain",
			prefix:    []byte("#!/usr/bin/env python3\nprint('unsafe')"),
			wantClass: FileTypeClassScript, wantReason: FileTypeReasonScript,
		},
		{
			name: "active payload appended to png is polyglot", declared: "image/png", detected: "image/png",
			prefix:    append(pngContentPrefix(), []byte("<script>alert(1)</script>")...),
			wantClass: FileTypeClassSuspiciousPolyglot, wantReason: FileTypeReasonSuspiciousPolyglot,
		},
		{
			name: "encoded active payload appended to png is polyglot", declared: "image/png", detected: "image/png",
			prefix:    append(pngContentPrefix(), utf16LEContentPrefix("<svg></svg>")...),
			wantClass: FileTypeClassSuspiciousPolyglot, wantReason: FileTypeReasonSuspiciousPolyglot,
		},
		{
			name: "zip signature appended to pdf is polyglot", declared: "application/pdf", detected: "application/pdf",
			prefix:    append([]byte("%PDF-1.7\n1 0 obj\n"), []byte{'P', 'K', 0x03, 0x04}...),
			wantClass: FileTypeClassSuspiciousPolyglot, wantReason: FileTypeReasonSuspiciousPolyglot,
		},
		{
			name: "malformed mz header is suspicious", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: []byte("MZ too short to attest PE"),
			wantClass: FileTypeClassSuspiciousContent, wantReason: FileTypeReasonSuspiciousContent,
		},
		{
			name: "malformed utf16 prefix is suspicious", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: []byte{0xff, 0xfe, '<'},
			wantClass: FileTypeClassSuspiciousContent, wantReason: FileTypeReasonSuspiciousContent,
		},
		{
			name: "empty prefix fails closed", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: nil,
			wantClass: FileTypeClassSuspiciousContent, wantReason: FileTypeReasonInvalidPrefix,
		},
		{
			name: "oversized prefix fails closed", declared: "application/octet-stream",
			detected: "application/octet-stream", prefix: oversized,
			wantClass: FileTypeClassSuspiciousContent, wantReason: FileTypeReasonInvalidPrefix,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := DecideFileType(FileTypeInput{
				DeclaredMIME: test.declared, DetectedMIME: test.detected, ContentPrefix: test.prefix,
			})
			if got := decision.Allowed(); got != test.wantAllow {
				t.Fatalf("Allowed() = %t, want %t; decision = %#v", got, test.wantAllow, decision)
			}
			if got := decision.Class(); got != test.wantClass {
				t.Errorf("Class() = %q, want %q", got, test.wantClass)
			}
			if got := decision.Reason(); got != test.wantReason {
				t.Errorf("Reason() = %q, want %q", got, test.wantReason)
			}
		})
	}
}

func pngContentPrefix() []byte {
	return []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R'}
}

func peContentPrefix() []byte {
	prefix := make([]byte, 128)
	copy(prefix, "MZ")
	prefix[0x3c] = 0x40
	copy(prefix[0x40:], []byte{'P', 'E', 0x00, 0x00})
	return prefix
}

func utf16LEContentPrefix(value string) []byte {
	prefix := []byte{0xff, 0xfe}
	for _, character := range []byte(value) {
		prefix = append(prefix, character, 0x00)
	}
	return prefix
}

func TestDecideFileTypeRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		detected string
	}{
		{name: "empty declared", declared: "", detected: "application/octet-stream"},
		{name: "empty detected", declared: "application/octet-stream", detected: ""},
		{name: "oversized declared", declared: "application/" + strings.Repeat("a", MaximumFileTypeMIMEBytes), detected: "application/octet-stream"},
		{name: "oversized detected", declared: "application/octet-stream", detected: "application/" + strings.Repeat("a", MaximumFileTypeMIMEBytes)},
		{name: "control character", declared: "text/plain\x00", detected: "text/plain"},
		{name: "invalid UTF-8", declared: "text/plain; note=\xff", detected: "text/plain"},
		{name: "newline", declared: "text/plain", detected: "text/plain\n"},
		{name: "directional control", declared: "text/plain; note=\u202eevil", detected: "text/plain"},
		{name: "wildcard", declared: "*/*", detected: "application/octet-stream"},
		{name: "malformed", declared: "not-a-mime", detected: "application/octet-stream"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := DecideFileType(FileTypeInput{
				ContentPrefix: []byte("bounded fixture content"),
				DeclaredMIME:  test.declared,
				DetectedMIME:  test.detected,
			})
			if decision.Allowed() || decision.Verdict() != FileTypeVerdictReject ||
				decision.Class() != FileTypeClassUnknown || decision.Reason() != FileTypeReasonInvalidMIME {
				t.Fatalf("invalid input decision = %#v", decision)
			}
		})
	}
}

func TestFileTypeDecisionFormattingDoesNotExposeMIMEValues(t *testing.T) {
	const sensitiveParameter = "customer-secret-marker"
	input := FileTypeInput{
		ContentPrefix: []byte(sensitiveParameter),
		DeclaredMIME:  "application/octet-stream; note=" + sensitiveParameter,
		DetectedMIME:  "application/octet-stream; note=" + sensitiveParameter,
	}
	decision := DecideFileType(input)
	if !decision.Allowed() {
		t.Fatalf("decision = %#v, want allow", decision)
	}
	for _, rendered := range []string{fmt.Sprint(decision), fmt.Sprintf("%#v", decision)} {
		if strings.Contains(rendered, sensitiveParameter) || strings.Contains(rendered, "application/octet-stream") {
			t.Fatalf("decision formatting exposed MIME metadata: %q", rendered)
		}
		if !strings.Contains(rendered, string(FileTypeReasonConsistentBinary)) {
			t.Fatalf("decision formatting omitted safe reason: %q", rendered)
		}
	}
	for _, rendered := range []string{fmt.Sprint(input), fmt.Sprintf("%#v", input)} {
		if strings.Contains(rendered, sensitiveParameter) {
			t.Fatalf("input formatting exposed content or MIME metadata: %q", rendered)
		}
	}
}

func TestZeroFileTypeDecisionFailsClosed(t *testing.T) {
	var decision FileTypeDecision
	if decision.Allowed() || decision.Verdict() != FileTypeVerdictReject ||
		decision.Class() != FileTypeClassUnknown || decision.Reason() != FileTypeReasonInvalidMIME {
		t.Fatalf("zero decision did not fail closed: %#v", decision)
	}
}
