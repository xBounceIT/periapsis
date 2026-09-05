package dfir

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
)

type ObjectLocation struct {
	Bucket string
	Key    string
}

func (location ObjectLocation) String() string {
	return "dfir.ObjectLocation{bucket:[REDACTED],key:[REDACTED]}"
}

func (location ObjectLocation) GoString() string { return location.String() }

type UploadHeader struct {
	Name  string
	Value string
}

type UploadGrant struct {
	TargetURL string
	Method    string
	Headers   []UploadHeader
	ExpiresAt time.Time
}

func (grant UploadGrant) String() string {
	return fmt.Sprintf("dfir.UploadGrant{method:%s,expiresAt:%s,target:[REDACTED],headers:[REDACTED]}", grant.Method, grant.ExpiresAt.Format(time.RFC3339))
}

func (grant UploadGrant) GoString() string { return grant.String() }

func (grant UploadGrant) clone() UploadGrant {
	result := grant
	result.Headers = slices.Clone(grant.Headers)
	return result
}

type ObjectReader struct {
	Body         io.ReadCloser
	SizeBytes    int64
	ContentType  string
	DeclaredMIME string
}

// ObjectStorage must target an already configured bucket/key through a
// transport that enforces the deployment egress, TLS, and credential policy.
type ObjectStorage interface {
	PrepareUpload(context.Context, ObjectLocation, int64, string, time.Time) (UploadGrant, error)
	PrepareDownload(context.Context, ObjectLocation, time.Time) (DownloadGrant, error)
	Open(context.Context, ObjectLocation) (ObjectReader, error)
}

// ObjectDeleter is kept separate from browser upload/download so only the
// fenced orphan-cleanup worker receives deletion authority.
type ObjectDeleter interface {
	Delete(context.Context, ObjectLocation) error
}

type DownloadGrant struct {
	TargetURL string
	ExpiresAt time.Time
}

func (grant DownloadGrant) String() string {
	return fmt.Sprintf("dfir.DownloadGrant{expiresAt:%s,target:[REDACTED]}", grant.ExpiresAt.Format(time.RFC3339))
}

func (grant DownloadGrant) GoString() string { return grant.String() }

type ScanVerdict string

const (
	ScanVerdictClean     ScanVerdict = "clean"
	ScanVerdictMalicious ScanVerdict = "malicious"
	ScanVerdictFailed    ScanVerdict = "failed"
)

type MalwareScanner interface {
	Scan(context.Context, io.Reader, int64) (ScanVerdict, error)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(target []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(target)
}

func sniffMediaType(value []byte) string {
	if len(value) == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(value)
}
