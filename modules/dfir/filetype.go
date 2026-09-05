package dfir

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"mime"
	"strings"
)

// MaximumFileTypeMIMEBytes bounds each untrusted MIME value accepted by the
// file-type policy.
const MaximumFileTypeMIMEBytes = 512

// MaximumFileTypeContentPrefixBytes bounds the independently sampled object
// prefix inspected for file signatures. The caller must provide at least one
// byte from the same stream that is subsequently hashed and scanned.
const MaximumFileTypeContentPrefixBytes = 8 * 1024

// FileTypeVerdict is the availability decision produced by DecideFileType.
type FileTypeVerdict string

const (
	// FileTypeVerdictAllow permits a recognized, passive file type to continue
	// through the scan pipeline. It does not by itself make an object available.
	FileTypeVerdictAllow FileTypeVerdict = "allow"
	// FileTypeVerdictReject keeps an object unavailable.
	FileTypeVerdictReject FileTypeVerdict = "reject"
)

// FileTypeClass is the security-relevant classification of a file-type
// decision.
type FileTypeClass string

const (
	FileTypeClassPassive            FileTypeClass = "passive"
	FileTypeClassGenericBinary      FileTypeClass = "generic_binary"
	FileTypeClassActiveContent      FileTypeClass = "active_content"
	FileTypeClassExecutable         FileTypeClass = "executable"
	FileTypeClassScript             FileTypeClass = "script"
	FileTypeClassSuspiciousMismatch FileTypeClass = "suspicious_mismatch"
	FileTypeClassSuspiciousContent  FileTypeClass = "suspicious_content"
	FileTypeClassSuspiciousPolyglot FileTypeClass = "suspicious_polyglot"
	FileTypeClassUnknown            FileTypeClass = "unknown"
)

// FileTypeReason is a stable, content-free reason code suitable for audit and
// telemetry dimensions.
type FileTypeReason string

const (
	FileTypeReasonConsistentPassive  FileTypeReason = "consistent_passive"
	FileTypeReasonConsistentBinary   FileTypeReason = "consistent_generic_binary"
	FileTypeReasonInvalidMIME        FileTypeReason = "invalid_mime"
	FileTypeReasonUnknownMIME        FileTypeReason = "unknown_mime"
	FileTypeReasonActiveContent      FileTypeReason = "active_content"
	FileTypeReasonExecutable         FileTypeReason = "executable"
	FileTypeReasonScript             FileTypeReason = "script"
	FileTypeReasonMIMEMismatch       FileTypeReason = "mime_mismatch"
	FileTypeReasonInvalidPrefix      FileTypeReason = "invalid_content_prefix"
	FileTypeReasonContentMismatch    FileTypeReason = "content_mismatch"
	FileTypeReasonSuspiciousContent  FileTypeReason = "suspicious_content"
	FileTypeReasonSuspiciousPolyglot FileTypeReason = "suspicious_polyglot"
)

// FileTypeInput contains the two independent MIME observations and a bounded
// prefix from the same object stream. It intentionally has no filename field,
// and decisions never retain the content prefix.
type FileTypeInput struct {
	DeclaredMIME  string
	DetectedMIME  string
	ContentPrefix []byte
}

func (input FileTypeInput) String() string {
	return "dfir.FileTypeInput{mime:[REDACTED],contentPrefix:[REDACTED]}"
}

func (input FileTypeInput) GoString() string { return input.String() }

// FileTypeDecision is an immutable, fail-closed result. Its default formatting
// omits both MIME values so it is safe to include in structured diagnostic
// output. Callers that need the normalized observations must opt in through
// the accessors.
type FileTypeDecision struct {
	verdict      FileTypeVerdict
	class        FileTypeClass
	reason       FileTypeReason
	declaredMIME string
	detectedMIME string
}

// Verdict reports allow or reject. The zero value rejects.
func (decision FileTypeDecision) Verdict() FileTypeVerdict {
	if decision.verdict == FileTypeVerdictAllow {
		return FileTypeVerdictAllow
	}
	return FileTypeVerdictReject
}

// Class reports the security classification. The zero value is unknown.
func (decision FileTypeDecision) Class() FileTypeClass {
	if decision.class == "" {
		return FileTypeClassUnknown
	}
	return decision.class
}

// Reason reports a stable reason code. The zero value is invalid_mime.
func (decision FileTypeDecision) Reason() FileTypeReason {
	if decision.reason == "" {
		return FileTypeReasonInvalidMIME
	}
	return decision.reason
}

// Allowed reports whether the policy permits the file type to continue. A
// separate clean scanner verdict and all storage invariants are still required.
func (decision FileTypeDecision) Allowed() bool {
	return decision.Verdict() == FileTypeVerdictAllow
}

// CanonicalDeclaredMIME returns the normalized declared MIME value, or an empty
// string when that input was invalid.
func (decision FileTypeDecision) CanonicalDeclaredMIME() string { return decision.declaredMIME }

// CanonicalDetectedMIME returns the normalized detected MIME value, or an empty
// string when that input was invalid.
func (decision FileTypeDecision) CanonicalDetectedMIME() string { return decision.detectedMIME }

func (decision FileTypeDecision) String() string {
	return fmt.Sprintf(
		"dfir.FileTypeDecision{verdict:%s,class:%s,reason:%s,mime:[REDACTED]}",
		decision.Verdict(), decision.Class(), decision.Reason(),
	)
}

func (decision FileTypeDecision) GoString() string { return decision.String() }

// DecideFileType compares independently declared and detected MIME values with
// a bounded prefix sampled from the same object stream. It allows only
// matching, recognized passive types whose content does not contradict those
// observations; every other state rejects.
func DecideFileType(input FileTypeInput) FileTypeDecision {
	declared, declaredOK := canonicalFileTypeMIME(input.DeclaredMIME)
	detected, detectedOK := canonicalFileTypeMIME(input.DetectedMIME)
	if !declaredOK || !detectedOK {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassUnknown,
			FileTypeReasonInvalidMIME,
			declared.formatted,
			detected.formatted,
		)
	}
	if len(input.ContentPrefix) == 0 || len(input.ContentPrefix) > MaximumFileTypeContentPrefixBytes {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassSuspiciousContent,
			FileTypeReasonInvalidPrefix,
			declared.formatted,
			detected.formatted,
		)
	}

	content := inspectFileTypeContent(input.ContentPrefix)
	if content.polyglot {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassSuspiciousPolyglot,
			FileTypeReasonSuspiciousPolyglot,
			declared.formatted,
			detected.formatted,
		)
	}
	if content.suspicious {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassSuspiciousContent,
			FileTypeReasonSuspiciousContent,
			declared.formatted,
			detected.formatted,
		)
	}
	if content.class == FileTypeClassActiveContent ||
		content.class == FileTypeClassExecutable ||
		content.class == FileTypeClassScript {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			content.class,
			reasonForUnsafeClass(content.class),
			declared.formatted,
			detected.formatted,
		)
	}

	// The independently detected observation has attribution priority when the
	// two inputs name different unsafe classes. The declaration is still checked
	// so a dangerous claim cannot be laundered through a generic detector result.
	for _, candidate := range []canonicalFileType{detected, declared} {
		switch candidate.class {
		case FileTypeClassActiveContent:
			return newFileTypeDecision(
				FileTypeVerdictReject,
				FileTypeClassActiveContent,
				FileTypeReasonActiveContent,
				declared.formatted,
				detected.formatted,
			)
		case FileTypeClassExecutable:
			return newFileTypeDecision(
				FileTypeVerdictReject,
				FileTypeClassExecutable,
				FileTypeReasonExecutable,
				declared.formatted,
				detected.formatted,
			)
		case FileTypeClassScript:
			return newFileTypeDecision(
				FileTypeVerdictReject,
				FileTypeClassScript,
				FileTypeReasonScript,
				declared.formatted,
				detected.formatted,
			)
		}
	}

	if declared.class == FileTypeClassUnknown || detected.class == FileTypeClassUnknown {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassUnknown,
			FileTypeReasonUnknownMIME,
			declared.formatted,
			detected.formatted,
		)
	}
	if declared.essence != detected.essence {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassSuspiciousMismatch,
			FileTypeReasonMIMEMismatch,
			declared.formatted,
			detected.formatted,
		)
	}
	if len(content.acceptedMIMEs) > 0 &&
		(!containsMIME(content.acceptedMIMEs, declared.essence) ||
			!containsMIME(content.acceptedMIMEs, detected.essence)) {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassSuspiciousMismatch,
			FileTypeReasonContentMismatch,
			declared.formatted,
			detected.formatted,
		)
	}
	if contentSignatureRequired(declared.essence) && len(content.acceptedMIMEs) == 0 {
		return newFileTypeDecision(
			FileTypeVerdictReject,
			FileTypeClassSuspiciousMismatch,
			FileTypeReasonContentMismatch,
			declared.formatted,
			detected.formatted,
		)
	}

	if detected.class == FileTypeClassGenericBinary {
		return newFileTypeDecision(
			FileTypeVerdictAllow,
			FileTypeClassGenericBinary,
			FileTypeReasonConsistentBinary,
			declared.formatted,
			detected.formatted,
		)
	}
	return newFileTypeDecision(
		FileTypeVerdictAllow,
		FileTypeClassPassive,
		FileTypeReasonConsistentPassive,
		declared.formatted,
		detected.formatted,
	)
}

func newFileTypeDecision(
	verdict FileTypeVerdict,
	class FileTypeClass,
	reason FileTypeReason,
	declaredMIME string,
	detectedMIME string,
) FileTypeDecision {
	return FileTypeDecision{
		verdict: verdict, class: class, reason: reason,
		declaredMIME: declaredMIME, detectedMIME: detectedMIME,
	}
}

type canonicalFileType struct {
	formatted string
	essence   string
	class     FileTypeClass
}

type fileTypeContentInspection struct {
	acceptedMIMEs []string
	class         FileTypeClass
	polyglot      bool
	suspicious    bool
}

func inspectFileTypeContent(prefix []byte) fileTypeContentInspection {
	var result fileTypeContentInspection
	switch {
	case bytes.HasPrefix(prefix, []byte("MZ")):
		if !hasPESignatureAt(prefix, 0) {
			return fileTypeContentInspection{suspicious: true}
		}
		result.class = FileTypeClassExecutable
	case bytes.HasPrefix(prefix, []byte{0x7f, 'E', 'L', 'F'}):
		result.class = FileTypeClassExecutable
	case bytes.HasPrefix(prefix, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}):
		result = passiveContent("image/png")
	case bytes.HasPrefix(prefix, []byte{0xff, 0xd8, 0xff}):
		result = passiveContent("image/jpeg")
	case bytes.HasPrefix(prefix, []byte("GIF87a")), bytes.HasPrefix(prefix, []byte("GIF89a")):
		result = passiveContent("image/gif")
	case bytes.HasPrefix(prefix, []byte("%PDF-")):
		result = passiveContent("application/pdf")
	case hasZIPSignature(prefix):
		result = passiveContent("application/zip")
	case bytes.HasPrefix(prefix, []byte{0x1f, 0x8b}):
		result = passiveContent("application/gzip", "application/x-gzip")
	case bytes.HasPrefix(prefix, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		result = passiveContent("application/x-7z-compressed")
	case bytes.HasPrefix(prefix, []byte("Rar!\x1a\x07\x00")),
		bytes.HasPrefix(prefix, []byte("Rar!\x1a\x07\x01\x00")):
		result = passiveContent("application/vnd.rar", "application/x-rar-compressed")
	case bytes.HasPrefix(prefix, []byte("BM")):
		result = passiveContent("image/bmp")
	case bytes.HasPrefix(prefix, []byte{'I', 'I', 0x2a, 0x00}),
		bytes.HasPrefix(prefix, []byte{'M', 'M', 0x00, 0x2a}):
		result = passiveContent("image/tiff")
	case len(prefix) >= 12 && bytes.Equal(prefix[:4], []byte("RIFF")) &&
		bytes.Equal(prefix[8:12], []byte("WEBP")):
		result = passiveContent("image/webp")
	default:
		var validEncoding bool
		result.class, validEncoding = classifyLeadingTextContent(prefix)
		if !validEncoding {
			result.suspicious = true
		}
	}

	unsafeClass := result.class == FileTypeClassActiveContent ||
		result.class == FileTypeClassExecutable || result.class == FileTypeClassScript
	if !unsafeClass && embeddedUnsafeContent(prefix) {
		if len(result.acceptedMIMEs) > 0 {
			result.polyglot = true
		} else {
			result.suspicious = true
		}
	}
	if len(result.acceptedMIMEs) > 0 &&
		embeddedConflictingSignature(prefix, result.acceptedMIMEs) {
		result.polyglot = true
	}
	return result
}

func passiveContent(acceptedMIMEs ...string) fileTypeContentInspection {
	return fileTypeContentInspection{
		acceptedMIMEs: acceptedMIMEs,
		class:         FileTypeClassPassive,
	}
}

func hasPESignatureAt(value []byte, start int) bool {
	const offsetLocation = 0x3c
	if start < 0 || len(value)-start < offsetLocation+4 ||
		!bytes.Equal(value[start:start+2], []byte("MZ")) {
		return false
	}
	headerOffset := uint64(binary.LittleEndian.Uint32(value[start+offsetLocation : start+offsetLocation+4]))
	headerStart := uint64(start) + headerOffset
	return headerOffset >= 0x40 && headerStart <= uint64(len(value)-4) &&
		bytes.Equal(value[headerStart:headerStart+4], []byte{'P', 'E', 0, 0})
}

func hasZIPSignature(value []byte) bool {
	return bytes.HasPrefix(value, []byte{'P', 'K', 0x03, 0x04}) ||
		bytes.HasPrefix(value, []byte{'P', 'K', 0x05, 0x06}) ||
		bytes.HasPrefix(value, []byte{'P', 'K', 0x07, 0x08})
}

func classifyLeadingTextContent(prefix []byte) (FileTypeClass, bool) {
	value, validEncoding := normalizedTextPrefix(prefix)
	if !validEncoding {
		return "", false
	}
	return classifyNormalizedTextContent(value), true
}

func classifyNormalizedTextContent(value []byte) FileTypeClass {
	value = bytes.TrimLeft(value, " \t\r\n\f")
	lower := bytes.ToLower(value)
	if bytes.HasPrefix(lower, []byte("#!")) ||
		bytes.HasPrefix(lower, []byte("<?php")) ||
		bytes.HasPrefix(lower, []byte("@echo off")) ||
		bytes.HasPrefix(lower, []byte("#requires")) {
		return FileTypeClassScript
	}
	for bytes.HasPrefix(lower, []byte("<!--")) {
		end := bytes.Index(lower, []byte("-->"))
		if end < 0 {
			return FileTypeClassActiveContent
		}
		lower = bytes.TrimLeft(lower[end+3:], " \t\r\n\f")
	}
	if bytes.HasPrefix(lower, []byte("<!doctype")) ||
		bytes.HasPrefix(lower, []byte("<?xml")) ||
		hasMarkupTagPrefix(lower, "html") ||
		hasMarkupTagPrefix(lower, "head") ||
		hasMarkupTagPrefix(lower, "body") ||
		hasMarkupTagPrefix(lower, "script") ||
		hasMarkupTagPrefix(lower, "svg") ||
		hasXMLLikeTagPrefix(lower) {
		return FileTypeClassActiveContent
	}
	return ""
}

func normalizedTextPrefix(prefix []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(prefix, []byte{0xff, 0xfe, 0x00, 0x00}):
		return normalizedFixedWidthASCII(prefix[4:], 4, true)
	case bytes.HasPrefix(prefix, []byte{0x00, 0x00, 0xfe, 0xff}):
		return normalizedFixedWidthASCII(prefix[4:], 4, false)
	case bytes.HasPrefix(prefix, []byte{0xff, 0xfe}):
		return normalizedFixedWidthASCII(prefix[2:], 2, true)
	case bytes.HasPrefix(prefix, []byte{0xfe, 0xff}):
		return normalizedFixedWidthASCII(prefix[2:], 2, false)
	default:
		return bytes.TrimPrefix(prefix, []byte{0xef, 0xbb, 0xbf}), true
	}
}

func normalizedFixedWidthASCII(value []byte, width int, littleEndian bool) ([]byte, bool) {
	if len(value)%width != 0 {
		return nil, false
	}
	normalized := make([]byte, 0, len(value)/width)
	for offset := 0; offset < len(value); {
		unit := value[offset : offset+width]
		var codePoint uint32
		if littleEndian {
			for index := width - 1; index >= 0; index-- {
				codePoint = codePoint<<8 | uint32(unit[index])
			}
		} else {
			for _, octet := range unit {
				codePoint = codePoint<<8 | uint32(octet)
			}
		}
		offset += width
		if width == 2 && codePoint >= 0xd800 && codePoint <= 0xdbff {
			if offset >= len(value) {
				return nil, false
			}
			nextUnit := value[offset : offset+width]
			var next uint32
			if littleEndian {
				next = uint32(nextUnit[1])<<8 | uint32(nextUnit[0])
			} else {
				next = uint32(nextUnit[0])<<8 | uint32(nextUnit[1])
			}
			if next < 0xdc00 || next > 0xdfff {
				return nil, false
			}
			offset += width
			normalized = append(normalized, '?')
			continue
		}
		if codePoint > 0x10ffff || codePoint >= 0xd800 && codePoint <= 0xdfff {
			return nil, false
		}
		if codePoint <= 0x7f {
			normalized = append(normalized, byte(codePoint))
		} else {
			normalized = append(normalized, '?')
		}
	}
	return normalized, true
}

func hasMarkupTagPrefix(value []byte, tag string) bool {
	prefix := []byte("<" + tag)
	if !bytes.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return false
	}
	switch value[len(prefix)] {
	case ' ', '\t', '\r', '\n', '\f', '>', '/':
		return true
	default:
		return false
	}
}

func hasXMLLikeTagPrefix(value []byte) bool {
	if len(value) < 3 || value[0] != '<' {
		return false
	}
	index := 1
	if value[index] == '/' {
		index++
		if index >= len(value) {
			return false
		}
	}
	first := value[index]
	if first != ':' && first != '_' && (first < 'a' || first > 'z') {
		return false
	}
	for index++; index < len(value); index++ {
		character := value[index]
		switch {
		case character == '>' || character == '/' || character == ' ' ||
			character == '\t' || character == '\r' || character == '\n' || character == '\f':
			return true
		case character == ':' || character == '_' || character == '-' || character == '.' ||
			character >= 'a' && character <= 'z' || character >= '0' && character <= '9':
			continue
		default:
			return false
		}
	}
	return false
}

func embeddedUnsafeContent(prefix []byte) bool {
	lower := bytes.ToLower(prefix)
	for _, marker := range [][]byte{
		[]byte("<!doctype html"),
		[]byte("<html"),
		[]byte("<script"),
		[]byte("<svg"),
		[]byte("<?xml"),
		[]byte("<?php"),
		[]byte("#!/"),
		[]byte("@echo off"),
		[]byte("#requires"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	if bytes.Contains(prefix[1:], []byte{0x7f, 'E', 'L', 'F'}) {
		return true
	}
	if embeddedEncodedUnsafeContent(prefix) {
		return true
	}
	for searchFrom := 1; searchFrom < len(prefix)-1; {
		relative := bytes.Index(prefix[searchFrom:], []byte("MZ"))
		if relative < 0 {
			break
		}
		start := searchFrom + relative
		if hasPESignatureAt(prefix, start) {
			return true
		}
		searchFrom = start + 2
	}
	return false
}

func embeddedEncodedUnsafeContent(prefix []byte) bool {
	encodings := []struct {
		byteOrderMark []byte
		width         int
		littleEndian  bool
	}{
		{byteOrderMark: []byte{0xff, 0xfe, 0x00, 0x00}, width: 4, littleEndian: true},
		{byteOrderMark: []byte{0x00, 0x00, 0xfe, 0xff}, width: 4},
		{byteOrderMark: []byte{0xff, 0xfe}, width: 2, littleEndian: true},
		{byteOrderMark: []byte{0xfe, 0xff}, width: 2},
	}
	for _, encoding := range encodings {
		for searchFrom := 1; searchFrom < len(prefix); {
			relative := bytes.Index(prefix[searchFrom:], encoding.byteOrderMark)
			if relative < 0 {
				break
			}
			start := searchFrom + relative + len(encoding.byteOrderMark)
			availableUnits := (len(prefix) - start) / encoding.width
			if availableUnits > 256 {
				availableUnits = 256
			}
			value, validEncoding := normalizedFixedWidthASCII(
				prefix[start:start+availableUnits*encoding.width],
				encoding.width,
				encoding.littleEndian,
			)
			if validEncoding {
				class := classifyNormalizedTextContent(value)
				if class == FileTypeClassActiveContent || class == FileTypeClassScript {
					return true
				}
			}
			searchFrom = start
		}
	}

	const utf8BOM = "\xef\xbb\xbf"
	for searchFrom := 1; searchFrom < len(prefix); {
		relative := bytes.Index(prefix[searchFrom:], []byte(utf8BOM))
		if relative < 0 {
			break
		}
		start := searchFrom + relative
		class, _ := classifyLeadingTextContent(prefix[start:])
		if class == FileTypeClassActiveContent || class == FileTypeClassScript {
			return true
		}
		searchFrom = start + len(utf8BOM)
	}
	return false
}

func embeddedConflictingSignature(prefix []byte, primaryMIMEs []string) bool {
	signatures := []struct {
		magic []byte
		mimes []string
	}{
		{magic: []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, mimes: []string{"image/png"}},
		{magic: []byte{0xff, 0xd8, 0xff, 0xe0}, mimes: []string{"image/jpeg"}},
		{magic: []byte{0xff, 0xd8, 0xff, 0xe1}, mimes: []string{"image/jpeg"}},
		{magic: []byte("GIF87a"), mimes: []string{"image/gif"}},
		{magic: []byte("GIF89a"), mimes: []string{"image/gif"}},
		{magic: []byte("%PDF-"), mimes: []string{"application/pdf"}},
		{magic: []byte{'P', 'K', 0x03, 0x04}, mimes: []string{"application/zip"}},
		{magic: []byte{'P', 'K', 0x05, 0x06}, mimes: []string{"application/zip"}},
		{magic: []byte{'P', 'K', 0x07, 0x08}, mimes: []string{"application/zip"}},
		{magic: []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, mimes: []string{"application/x-7z-compressed"}},
		{magic: []byte("Rar!\x1a\x07"), mimes: []string{"application/vnd.rar", "application/x-rar-compressed"}},
		{magic: []byte{'I', 'I', 0x2a, 0x00}, mimes: []string{"image/tiff"}},
		{magic: []byte{'M', 'M', 0x00, 0x2a}, mimes: []string{"image/tiff"}},
	}
	for _, signature := range signatures {
		if sharesMIME(primaryMIMEs, signature.mimes) {
			continue
		}
		if bytes.Contains(prefix[1:], signature.magic) {
			return true
		}
	}
	if !containsMIME(primaryMIMEs, "image/webp") {
		for searchFrom := 1; searchFrom+12 <= len(prefix); {
			relative := bytes.Index(prefix[searchFrom:], []byte("RIFF"))
			if relative < 0 {
				break
			}
			start := searchFrom + relative
			if start+12 <= len(prefix) && bytes.Equal(prefix[start+8:start+12], []byte("WEBP")) {
				return true
			}
			searchFrom = start + 4
		}
	}
	return false
}

func reasonForUnsafeClass(class FileTypeClass) FileTypeReason {
	switch class {
	case FileTypeClassActiveContent:
		return FileTypeReasonActiveContent
	case FileTypeClassExecutable:
		return FileTypeReasonExecutable
	case FileTypeClassScript:
		return FileTypeReasonScript
	default:
		return FileTypeReasonSuspiciousContent
	}
}

func containsMIME(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func sharesMIME(left []string, right []string) bool {
	for _, candidate := range left {
		if containsMIME(right, candidate) {
			return true
		}
	}
	return false
}

func contentSignatureRequired(mediaType string) bool {
	switch mediaType {
	case "application/gzip", "application/pdf", "application/vnd.rar",
		"application/x-7z-compressed", "application/x-gzip", "application/x-rar-compressed",
		"application/zip", "image/bmp", "image/gif", "image/jpeg", "image/png",
		"image/tiff", "image/webp":
		return true
	default:
		return false
	}
}

func canonicalFileTypeMIME(value string) (canonicalFileType, bool) {
	if !validSingleLineText(value, MaximumFileTypeMIMEBytes, false) {
		return canonicalFileType{}, false
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	mediaType = strings.ToLower(mediaType)
	if err != nil || !validMIMEEssence(mediaType) {
		return canonicalFileType{}, false
	}
	canonicalParameters := make(map[string]string, len(parameters))
	for key, parameter := range parameters {
		key = strings.ToLower(key)
		if key == "charset" {
			parameter = strings.ToLower(parameter)
		}
		canonicalParameters[key] = parameter
	}
	formatted := mime.FormatMediaType(mediaType, canonicalParameters)
	if !validSingleLineText(formatted, MaximumFileTypeMIMEBytes, false) {
		return canonicalFileType{}, false
	}
	return canonicalFileType{
		formatted: formatted,
		essence:   mediaType,
		class:     classifyFileTypeMIME(mediaType),
	}, true
}

func validMIMEEssence(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != "" &&
		parts[0] != "*" && parts[1] != "*"
}

func classifyFileTypeMIME(value string) FileTypeClass {
	if isActiveContentMIME(value) {
		return FileTypeClassActiveContent
	}
	if _, ok := executableMIMETypes[value]; ok {
		return FileTypeClassExecutable
	}
	if _, ok := scriptMIMETypes[value]; ok {
		return FileTypeClassScript
	}
	if value == "application/octet-stream" {
		return FileTypeClassGenericBinary
	}
	if _, ok := passiveMIMETypes[value]; ok {
		return FileTypeClassPassive
	}
	return FileTypeClassUnknown
}

func isActiveContentMIME(value string) bool {
	return value == "text/html" || value == "application/xhtml+xml" ||
		value == "image/svg+xml" || value == "application/xml" ||
		value == "text/xml" || strings.HasSuffix(value, "+xml")
}

var executableMIMETypes = map[string]struct{}{
	"application/java-archive":                      {},
	"application/wasm":                              {},
	"application/x-dosexec":                         {},
	"application/x-elf":                             {},
	"application/x-executable":                      {},
	"application/x-java-applet":                     {},
	"application/x-java-archive":                    {},
	"application/x-mach-binary":                     {},
	"application/x-msdos-program":                   {},
	"application/x-msdownload":                      {},
	"application/x-object":                          {},
	"application/x-pie-executable":                  {},
	"application/x-sharedlib":                       {},
	"application/vnd.microsoft.portable-executable": {},
}

var scriptMIMETypes = map[string]struct{}{
	"application/ecmascript":    {},
	"application/javascript":    {},
	"application/postscript":    {},
	"application/x-bat":         {},
	"application/x-csh":         {},
	"application/x-httpd-php":   {},
	"application/x-javascript":  {},
	"application/x-perl":        {},
	"application/x-powershell":  {},
	"application/x-python-code": {},
	"application/x-ruby":        {},
	"application/x-sh":          {},
	"application/x-shellscript": {},
	"text/ecmascript":           {},
	"text/javascript":           {},
	"text/x-perl":               {},
	"text/x-php":                {},
	"text/x-powershell":         {},
	"text/x-python":             {},
	"text/x-ruby":               {},
	"text/x-script.python":      {},
	"text/x-shellscript":        {},
}

var passiveMIMETypes = map[string]struct{}{
	"application/gzip":             {},
	"application/json":             {},
	"application/pdf":              {},
	"application/vnd.rar":          {},
	"application/vnd.tcpdump.pcap": {},
	"application/x-7z-compressed":  {},
	"application/x-gzip":           {},
	"application/x-pcap":           {},
	"application/x-pcapng":         {},
	"application/x-rar-compressed": {},
	"application/x-tar":            {},
	"application/zip":              {},
	"audio/flac":                   {},
	"audio/mpeg":                   {},
	"audio/ogg":                    {},
	"audio/wav":                    {},
	"audio/webm":                   {},
	"image/bmp":                    {},
	"image/gif":                    {},
	"image/jpeg":                   {},
	"image/png":                    {},
	"image/tiff":                   {},
	"image/webp":                   {},
	"text/csv":                     {},
	"text/plain":                   {},
	"text/tab-separated-values":    {},
	"video/mp4":                    {},
	"video/mpeg":                   {},
	"video/quicktime":              {},
	"video/webm":                   {},
}
