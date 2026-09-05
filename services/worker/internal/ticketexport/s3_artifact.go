package ticketexport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	MaximumSpoolSweepEntries = 1_000
	MinimumSpoolSweepAge     = kernel.TicketExportMaximumLease + time.Minute
)

var s3ArtifactBucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var s3ArtifactSpoolPattern = regexp.MustCompile(`^\.ticket-export-[0-9]+\.partial$`)

type s3ArtifactAPI interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	CopyObject(context.Context, *s3.CopyObjectInput, ...func(*s3.Options)) (*s3.CopyObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3ArtifactOptions struct {
	Bucket              string
	ExpectedBucketOwner string
	TemporaryDirectory  string
}

func (S3ArtifactOptions) String() string {
	return "ticketexport.S3ArtifactOptions{storage:[REDACTED],filesystem:[REDACTED]}"
}

func (options S3ArtifactOptions) GoString() string { return options.String() }

// S3ArtifactStore stages bounded CSV bytes in an explicit writable temporary
// directory, uploads them with create-only semantics, then conditionally copies
// them to a tenant/job/artifact-derived final key. Every remote object uses
// SSE-S3 and private bucket-owner authorization; no query, cursor, header, or
// exported cell contributes to a key or metadata field.
type S3ArtifactStore struct {
	api                 s3ArtifactAPI
	bucket              string
	expectedBucketOwner *string
	temporaryDirectory  string
	removeFile          func(string) error
	spoolMu             sync.RWMutex
	activeSpools        map[string]struct{}
}

func NewS3ArtifactStore(api s3ArtifactAPI, options S3ArtifactOptions) (*S3ArtifactStore, error) {
	if nilInterface(api) || !validS3ArtifactBucket(options.Bucket) ||
		!validExpectedBucketOwner(options.ExpectedBucketOwner) ||
		!validS3ArtifactTemporaryDirectory(options.TemporaryDirectory) {
		return nil, ErrInvalidConfiguration
	}
	var owner *string
	if options.ExpectedBucketOwner != "" {
		owner = aws.String(options.ExpectedBucketOwner)
	}
	return &S3ArtifactStore{
		api: api, bucket: options.Bucket, expectedBucketOwner: owner,
		temporaryDirectory: options.TemporaryDirectory, removeFile: os.Remove,
		activeSpools: make(map[string]struct{}),
	}, nil
}

func (store *S3ArtifactStore) OpenTemporary(
	ctx context.Context,
	lifetime context.Context,
	request TemporaryRequest,
) (TemporaryArtifact, error) {
	if store == nil || nilInterface(store.api) || ctx == nil || ctx.Err() != nil ||
		lifetime == nil || lifetime.Err() != nil ||
		!validIdentity(request.Identity) || !validS3ArtifactBinding(request.Binding, request.Identity) ||
		!validEntityID(request.ArtifactID) || request.MaximumBytes == 0 ||
		request.MaximumBytes > s3ArtifactMaximumBytes(request.Binding.Audience) {
		return nil, ErrUnavailable
	}
	file, err := os.CreateTemp(store.temporaryDirectory, ".ticket-export-*.partial")
	if err != nil || file == nil {
		return nil, ErrUnavailable
	}
	info, statErr := file.Stat()
	if statErr != nil || info == nil || !info.Mode().IsRegular() || ctx.Err() != nil || lifetime.Err() != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, ErrUnavailable
	}
	temporaryKey, finalKey, keyErr := kernel.TicketExportArtifactObjectKeys(
		request.Binding.TenantID,
		request.Binding.JobID,
		request.ArtifactID,
	)
	if keyErr != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, ErrInvalidInput
	}
	store.retainSpool(file.Name())
	artifact := &s3TemporaryArtifact{
		store: store, lifetime: lifetime, file: file, localPath: file.Name(),
		binding: request.Binding, artifactID: request.ArtifactID,
		maximumBytes: request.MaximumBytes, digest: sha256.New(),
		temporaryKey: temporaryKey, finalKey: finalKey, state: s3ArtifactOpen,
		lifetimeFile: file,
	}
	artifact.stopLifetime = context.AfterFunc(lifetime, artifact.closeLifetimeFile)
	return artifact, nil
}

func (*S3ArtifactStore) String() string {
	return "ticketexport.S3ArtifactStore{storage:[REDACTED],filesystem:[REDACTED]}"
}

func (store *S3ArtifactStore) GoString() string { return store.String() }

// Check verifies the exact configured bucket and optional account owner before
// the worker advertises export readiness. It performs no list operation and
// never exposes bucket or provider diagnostics to callers.
func (store *S3ArtifactStore) Check(ctx context.Context) error {
	if store == nil || nilInterface(store.api) || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	result, err := store.api.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: store.bucketPointer(), ExpectedBucketOwner: store.expectedBucketOwner,
	})
	if err != nil || result == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

// PurgeArtifact derives the only two possible keys from immutable entity IDs,
// preflights both exact manifests, and then performs conditional deletes. It
// never lists a bucket and never trusts a persisted or caller-supplied key.
func (store *S3ArtifactStore) PurgeArtifact(
	ctx context.Context,
	artifact ReconcileArtifact,
) error {
	if store == nil || nilInterface(store.api) {
		return ErrUnavailable
	}
	if ctx == nil || !validReconcileArtifact(artifact) {
		return ErrInvalidInput
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	temporaryKey, finalKey, err := kernel.TicketExportArtifactObjectKeys(
		artifact.TenantID,
		artifact.JobID,
		artifact.ArtifactID,
	)
	if err != nil {
		return ErrInvalidInput
	}
	manifest := StreamManifest{
		ArtifactID: artifact.ArtifactID,
		Digest:     artifact.Digest,
		Rows:       artifact.Rows,
		Bytes:      artifact.Bytes,
	}
	temporaryHead, temporaryFound, err := store.head(ctx, temporaryKey)
	if err != nil {
		return ErrUnavailable
	}
	finalHead, finalFound, err := store.head(ctx, finalKey)
	if err != nil {
		return ErrUnavailable
	}
	if (temporaryFound && !store.validHead(
		temporaryHead,
		manifest,
		s3ArtifactMetadata(artifact, "temporary"),
	)) || (finalFound && !store.validHead(
		finalHead,
		manifest,
		s3ArtifactMetadata(artifact, "final"),
	)) {
		return ErrArtifactConflict
	}
	if temporaryFound {
		if err := store.deleteReconciledObject(ctx, temporaryKey, temporaryHead); err != nil {
			return err
		}
	}
	if finalFound {
		if err := store.deleteReconciledObject(ctx, finalKey, finalHead); err != nil {
			return err
		}
	}
	return nil
}

func (store *S3ArtifactStore) deleteReconciledObject(
	ctx context.Context,
	key string,
	expected *s3.HeadObjectOutput,
) error {
	if expected == nil || !validS3ArtifactETag(aws.ToString(expected.ETag)) {
		return ErrUnavailable
	}
	if err := store.deleteIfMatch(ctx, key, expected.ETag); err != nil {
		return ErrUnavailable
	}
	observed, found, err := store.head(ctx, key)
	if err != nil {
		return ErrUnavailable
	}
	if !found {
		return nil
	}
	if aws.ToString(observed.ETag) != aws.ToString(expected.ETag) {
		return ErrArtifactConflict
	}
	return ErrUnavailable
}

func (store *S3ArtifactStore) retainSpool(path string) {
	store.spoolMu.Lock()
	store.activeSpools[path] = struct{}{}
	store.spoolMu.Unlock()
}

func (store *S3ArtifactStore) releaseSpool(path string) {
	store.spoolMu.Lock()
	delete(store.activeSpools, path)
	store.spoolMu.Unlock()
}

func (store *S3ArtifactStore) spoolActive(path string) bool {
	store.spoolMu.RLock()
	_, active := store.activeSpools[path]
	store.spoolMu.RUnlock()
	return active
}

type SpoolSweepResult struct {
	Examined  uint32
	Removed   uint32
	Remaining bool
}

func (result SpoolSweepResult) String() string {
	return fmt.Sprintf(
		"ticketexport.SpoolSweepResult{examined:%d,removed:%d,remaining:%t,filesystem:[REDACTED]}",
		result.Examined, result.Removed, result.Remaining,
	)
}

func (result SpoolSweepResult) GoString() string { return result.String() }

// SweepSpoolsBefore removes only repository-owned local spool names whose
// last modification precedes cutoff. It is bounded by limit and is safe to
// replay after a process crash. Callers must choose a cutoff older than the
// maximum live attempt and invoke it from startup/periodic reconciliation.
func (store *S3ArtifactStore) SweepSpoolsBefore(
	ctx context.Context,
	cutoff time.Time,
	limit int,
) (SpoolSweepResult, error) {
	if store == nil || ctx == nil || !validInstant(cutoff) ||
		limit < 1 || limit > MaximumSpoolSweepEntries || store.removeFile == nil {
		return SpoolSweepResult{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return SpoolSweepResult{}, ErrInterrupted
	}
	latestSafeCutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-MinimumSpoolSweepAge)
	if cutoff.After(latestSafeCutoff) {
		return SpoolSweepResult{}, ErrInvalidInput
	}
	directory, err := os.Open(store.temporaryDirectory)
	if err != nil {
		return SpoolSweepResult{}, ErrUnavailable
	}
	defer directory.Close()
	entries, err := directory.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return SpoolSweepResult{}, ErrUnavailable
	}
	result := SpoolSweepResult{Remaining: len(entries) > limit}
	if result.Remaining {
		entries = entries[:limit]
	}
	cleanupPending := false
	for _, entry := range entries {
		if ctx.Err() != nil {
			return result, ErrInterrupted
		}
		result.Examined++
		if !s3ArtifactSpoolPattern.MatchString(entry.Name()) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(store.temporaryDirectory, entry.Name())
		if store.spoolActive(path) {
			continue
		}
		info, statErr := os.Lstat(path)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			cleanupPending = true
			continue
		}
		if !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		if removeErr := store.removeFile(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cleanupPending = true
			continue
		}
		result.Removed++
	}
	if cleanupPending {
		result.Remaining = true
		return result, ErrCleanupPending
	}
	return result, nil
}

type s3ArtifactState uint8

const (
	s3ArtifactOpen s3ArtifactState = iota + 1
	s3ArtifactSealed
	s3ArtifactPromoted
	s3ArtifactAborted
	s3ArtifactPurged
)

type s3TemporaryArtifact struct {
	mu           sync.Mutex
	fileCloseMu  sync.Mutex
	store        *S3ArtifactStore
	lifetime     context.Context
	file         *os.File
	lifetimeFile *os.File
	stopLifetime func() bool
	localPath    string
	binding      LeaseBinding
	artifactID   kernel.EntityID
	maximumBytes uint64
	digest       hash.Hash
	written      uint64
	manifest     *StreamManifest
	temporaryKey string
	finalKey     string
	state        s3ArtifactState
	poisoned     bool
}

func (artifact *s3TemporaryArtifact) Write(value []byte) (int, error) {
	if artifact == nil {
		return 0, ErrUnavailable
	}
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if artifact.state != s3ArtifactOpen || artifact.poisoned ||
		artifact.file == nil || artifact.lifetime == nil || artifact.lifetime.Err() != nil ||
		artifact.written > artifact.maximumBytes ||
		uint64(len(value)) > artifact.maximumBytes-artifact.written {
		artifact.poisoned = true
		return 0, ErrUnavailable
	}
	written, err := artifact.file.Write(value)
	if written > 0 {
		_, _ = artifact.digest.Write(value[:written])
		artifact.written += uint64(written)
	}
	if err != nil || written != len(value) || artifact.lifetime.Err() != nil {
		artifact.poisoned = true
		return written, ErrUnavailable
	}
	return written, nil
}

func (artifact *s3TemporaryArtifact) Seal(ctx context.Context, manifest StreamManifest) error {
	if artifact == nil {
		return ErrUnavailable
	}
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || artifact.store == nil ||
		nilInterface(artifact.store.api) || artifact.lifetime == nil || artifact.lifetime.Err() != nil {
		return ErrUnavailable
	}
	if artifact.state == s3ArtifactSealed || artifact.state == s3ArtifactPromoted {
		if artifact.manifest != nil && *artifact.manifest == manifest {
			return nil
		}
		return ErrUnavailable
	}
	if artifact.state != s3ArtifactOpen || artifact.poisoned || artifact.file == nil ||
		manifest.ArtifactID != artifact.artifactID || manifest.Digest == ([32]byte{}) ||
		manifest.Bytes == 0 || manifest.Bytes != artifact.written ||
		manifest.Bytes > artifact.maximumBytes ||
		manifest.Rows > s3ArtifactMaximumRows(artifact.binding.Audience) ||
		manifest.Digest != artifact.currentDigest() {
		artifact.poisoned = true
		return ErrUnavailable
	}
	ownedManifest := manifest
	artifact.manifest = &ownedManifest
	if err := artifact.file.Sync(); err != nil {
		artifact.poisoned = true
		return ErrUnavailable
	}
	if _, err := artifact.file.Seek(0, io.SeekStart); err != nil {
		artifact.poisoned = true
		return ErrUnavailable
	}
	temporaryMetadata := artifact.metadata(manifest, "temporary")
	head, found, err := artifact.store.head(ctx, artifact.temporaryKey)
	if err != nil {
		return ErrUnavailable
	}
	if found {
		if !artifact.store.validHead(head, manifest, temporaryMetadata) {
			return ErrUnavailable
		}
		return artifact.finishSeal(manifest)
	}
	contentType := "text/csv; charset=utf-8"
	checksum := base64.StdEncoding.EncodeToString(manifest.Digest[:])
	_, _ = artifact.store.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket: artifact.store.bucketPointer(), Key: aws.String(artifact.temporaryKey),
		Body: artifact.file, ContentLength: aws.Int64(int64(manifest.Bytes)),
		ContentType: aws.String(contentType), Metadata: temporaryMetadata,
		ChecksumSHA256: aws.String(checksum), IfNoneMatch: aws.String("*"),
		ChecksumAlgorithm:    types.ChecksumAlgorithmSha256,
		ServerSideEncryption: types.ServerSideEncryptionAes256,
		ExpectedBucketOwner:  artifact.store.expectedBucketOwner,
	})
	head, found, headErr := artifact.store.head(ctx, artifact.temporaryKey)
	if headErr != nil || !found || !artifact.store.validHead(head, manifest, temporaryMetadata) {
		return ErrUnavailable
	}
	// A post-write response can be lost. Exact HEAD reconciliation proves the
	// create-only upload before the local spool is discarded.
	return artifact.finishSeal(manifest)
}

func (artifact *s3TemporaryArtifact) Promote(
	ctx context.Context,
	artifactID kernel.EntityID,
) (PromotionDisposition, error) {
	if artifact == nil {
		return PromotionRejected, ErrUnavailable
	}
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || artifact.store == nil ||
		nilInterface(artifact.store.api) || artifactID != artifact.artifactID || artifact.manifest == nil {
		return PromotionRejected, ErrUnavailable
	}
	if artifact.state == s3ArtifactPromoted {
		return PromotionReplayed, nil
	}
	if artifact.state != s3ArtifactSealed {
		return PromotionRejected, ErrUnavailable
	}
	finalMetadata := artifact.metadata(*artifact.manifest, "final")
	finalHead, finalFound, err := artifact.store.head(ctx, artifact.finalKey)
	if err != nil {
		return PromotionRejected, ErrUnavailable
	}
	if finalFound {
		if !artifact.store.validHead(finalHead, *artifact.manifest, finalMetadata) {
			return PromotionRejected, nil
		}
		if deleteErr := artifact.deleteExact(ctx, artifact.temporaryKey, "temporary"); deleteErr != nil {
			return PromotionRejected, ErrUnavailable
		}
		artifact.state = s3ArtifactPromoted
		return PromotionReplayed, nil
	}
	temporaryHead, temporaryFound, err := artifact.store.head(ctx, artifact.temporaryKey)
	if err != nil || !temporaryFound ||
		!artifact.store.validHead(
			temporaryHead, *artifact.manifest, artifact.metadata(*artifact.manifest, "temporary"),
		) {
		return PromotionRejected, ErrUnavailable
	}
	contentType := "text/csv; charset=utf-8"
	copySource := url.PathEscape(artifact.store.bucket + "/" + artifact.temporaryKey)
	_, _ = artifact.store.api.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket: artifact.store.bucketPointer(), Key: aws.String(artifact.finalKey),
		CopySource: aws.String(copySource), CopySourceIfMatch: temporaryHead.ETag,
		IfNoneMatch: aws.String("*"), MetadataDirective: types.MetadataDirectiveReplace,
		Metadata: finalMetadata, ContentType: aws.String(contentType),
		ChecksumAlgorithm:         types.ChecksumAlgorithmSha256,
		ServerSideEncryption:      types.ServerSideEncryptionAes256,
		ExpectedBucketOwner:       artifact.store.expectedBucketOwner,
		ExpectedSourceBucketOwner: artifact.store.expectedBucketOwner,
	})
	finalHead, finalFound, headErr := artifact.store.head(ctx, artifact.finalKey)
	if headErr != nil || !finalFound ||
		!artifact.store.validHead(finalHead, *artifact.manifest, finalMetadata) {
		if finalFound {
			return PromotionRejected, nil
		}
		return PromotionRejected, ErrUnavailable
	}
	// As with PUT, an exact final HEAD closes an outcome-ambiguous COPY.
	if deleteErr := artifact.deleteExact(ctx, artifact.temporaryKey, "temporary"); deleteErr != nil {
		return PromotionRejected, ErrUnavailable
	}
	artifact.state = s3ArtifactPromoted
	return PromotionApplied, nil
}

func (artifact *s3TemporaryArtifact) Abort(ctx context.Context) error {
	if artifact == nil {
		return ErrUnavailable
	}
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || artifact.store == nil {
		return ErrUnavailable
	}
	if artifact.state == s3ArtifactAborted || artifact.state == s3ArtifactPurged ||
		artifact.state == s3ArtifactPromoted {
		return nil
	}
	localErr := artifact.closeLocal()
	var remoteErr error
	if artifact.manifest != nil {
		remoteErr = artifact.deleteExact(ctx, artifact.temporaryKey, "temporary")
	}
	if localErr != nil || remoteErr != nil {
		return ErrUnavailable
	}
	artifact.state = s3ArtifactAborted
	return nil
}

func (artifact *s3TemporaryArtifact) Purge(ctx context.Context, artifactID kernel.EntityID) error {
	if artifact == nil {
		return ErrUnavailable
	}
	artifact.mu.Lock()
	defer artifact.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || artifact.store == nil ||
		artifactID != artifact.artifactID || artifact.manifest == nil {
		return ErrUnavailable
	}
	if artifact.state == s3ArtifactPurged {
		return nil
	}
	localErr := artifact.closeLocal()
	temporaryErr := artifact.deleteExact(ctx, artifact.temporaryKey, "temporary")
	finalErr := artifact.deleteExact(ctx, artifact.finalKey, "final")
	if localErr != nil || temporaryErr != nil || finalErr != nil {
		return ErrUnavailable
	}
	artifact.state = s3ArtifactPurged
	return nil
}

func (*s3TemporaryArtifact) String() string {
	return "ticketexport.s3TemporaryArtifact{storage:[REDACTED],filesystem:[REDACTED],identity:[REDACTED]}"
}

func (artifact *s3TemporaryArtifact) GoString() string { return artifact.String() }

func (artifact *s3TemporaryArtifact) currentDigest() [sha256.Size]byte {
	var result [sha256.Size]byte
	copy(result[:], artifact.digest.Sum(nil))
	return result
}

func (artifact *s3TemporaryArtifact) finishSeal(manifest StreamManifest) error {
	if err := artifact.closeLocal(); err != nil {
		return ErrUnavailable
	}
	owned := manifest
	artifact.manifest = &owned
	artifact.state = s3ArtifactSealed
	return nil
}

func (artifact *s3TemporaryArtifact) closeLocal() error {
	var result error
	if artifact.file != nil {
		if artifact.stopLifetime != nil {
			artifact.stopLifetime()
			artifact.stopLifetime = nil
		}
		artifact.fileCloseMu.Lock()
		if artifact.lifetimeFile != nil {
			if err := artifact.lifetimeFile.Close(); err != nil {
				result = ErrUnavailable
			}
			artifact.lifetimeFile = nil
		}
		artifact.fileCloseMu.Unlock()
		if artifact.store == nil {
			result = ErrUnavailable
		}
		artifact.file = nil
		if artifact.store != nil && artifact.localPath != "" {
			artifact.store.releaseSpool(artifact.localPath)
		}
	}
	if artifact.localPath != "" {
		if artifact.store == nil || artifact.store.removeFile == nil {
			result = ErrUnavailable
		} else if err := artifact.store.removeFile(artifact.localPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = ErrUnavailable
		} else {
			artifact.localPath = ""
		}
	}
	return result
}

func (artifact *s3TemporaryArtifact) closeLifetimeFile() {
	artifact.fileCloseMu.Lock()
	if artifact.lifetimeFile != nil {
		_ = artifact.lifetimeFile.Close()
		artifact.lifetimeFile = nil
	}
	artifact.fileCloseMu.Unlock()
}

func (artifact *s3TemporaryArtifact) metadata(
	manifest StreamManifest,
	state string,
) map[string]string {
	return s3ArtifactMetadata(ReconcileArtifact{
		TenantID:          artifact.binding.TenantID,
		JobID:             artifact.binding.JobID,
		ArtifactID:        manifest.ArtifactID,
		Kind:              artifact.binding.Kind,
		Audience:          artifact.binding.Audience,
		ObjectRevision:    artifact.binding.Revision,
		ObjectAttempt:     artifact.binding.Attempt,
		ProjectionVersion: artifact.binding.ProjectionVersion,
		Digest:            manifest.Digest,
		Rows:              manifest.Rows,
		Bytes:             manifest.Bytes,
	}, state)
}

func s3ArtifactMetadata(
	artifact ReconcileArtifact,
	state string,
) map[string]string {
	return map[string]string{
		"periapsis-tenant":     artifact.TenantID.String(),
		"periapsis-job":        artifact.JobID.String(),
		"periapsis-artifact":   artifact.ArtifactID.String(),
		"periapsis-revision":   strconv.FormatUint(artifact.ObjectRevision, 10),
		"periapsis-attempt":    strconv.FormatUint(uint64(artifact.ObjectAttempt), 10),
		"periapsis-sha256":     hex.EncodeToString(artifact.Digest[:]),
		"periapsis-rows":       strconv.FormatUint(uint64(artifact.Rows), 10),
		"periapsis-bytes":      strconv.FormatUint(artifact.Bytes, 10),
		"periapsis-projection": strconv.FormatUint(artifact.ProjectionVersion, 10),
		"periapsis-state":      state,
	}
}

func (artifact *s3TemporaryArtifact) deleteExact(ctx context.Context, key, state string) error {
	head, found, err := artifact.store.head(ctx, key)
	if err != nil {
		return ErrUnavailable
	}
	if !found {
		return nil
	}
	metadata := artifact.metadata(*artifact.manifest, state)
	if !artifact.store.validHead(head, *artifact.manifest, metadata) {
		return ErrUnavailable
	}
	return artifact.store.deleteIfMatch(ctx, key, head.ETag)
}

func (store *S3ArtifactStore) head(
	ctx context.Context,
	key string,
) (*s3.HeadObjectOutput, bool, error) {
	result, err := store.api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: store.bucketPointer(), Key: aws.String(key),
		ExpectedBucketOwner: store.expectedBucketOwner, ChecksumMode: types.ChecksumModeEnabled,
	})
	if ctx.Err() != nil {
		return nil, false, ErrUnavailable
	}
	if err != nil {
		if s3ArtifactNotFound(err) {
			return nil, false, nil
		}
		return nil, false, ErrUnavailable
	}
	if result == nil {
		return nil, false, ErrUnavailable
	}
	return result, true, nil
}

func (store *S3ArtifactStore) deleteIfMatch(ctx context.Context, key string, etag *string) error {
	if !validS3ArtifactETag(aws.ToString(etag)) {
		return ErrUnavailable
	}
	result, err := store.api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: store.bucketPointer(), Key: aws.String(key),
		ExpectedBucketOwner: store.expectedBucketOwner, IfMatch: etag,
	})
	if ctx.Err() != nil || err != nil || result == nil {
		return ErrUnavailable
	}
	return nil
}

func (store *S3ArtifactStore) validHead(
	head *s3.HeadObjectOutput,
	manifest StreamManifest,
	metadata map[string]string,
) bool {
	if head == nil || aws.ToInt64(head.ContentLength) != int64(manifest.Bytes) ||
		aws.ToString(head.ContentType) != "text/csv; charset=utf-8" ||
		head.ServerSideEncryption != types.ServerSideEncryptionAes256 ||
		aws.ToString(head.ChecksumSHA256) != base64.StdEncoding.EncodeToString(manifest.Digest[:]) ||
		!validS3ArtifactETag(aws.ToString(head.ETag)) || len(head.Metadata) != len(metadata) {
		return false
	}
	for key, value := range metadata {
		if head.Metadata[key] != value {
			return false
		}
	}
	return true
}

func (store *S3ArtifactStore) bucketPointer() *string { return aws.String(store.bucket) }

func validS3ArtifactBinding(binding LeaseBinding, identity Identity) bool {
	return validEntityID(binding.TenantID) && validEntityID(binding.JobID) &&
		validEntityID(binding.WorkerID) && binding.WorkerID == identity.WorkerID &&
		(binding.Kind == kernel.AggregateAlert || binding.Kind == kernel.AggregateCase) &&
		(binding.Audience == kernel.TicketExportAudienceOperator ||
			binding.Audience == kernel.TicketExportAudienceCustomer) &&
		binding.Revision > 0 && binding.Revision <= math.MaxInt32 &&
		binding.Attempt > 0 && binding.Attempt <= kernel.TicketExportMaximumAttempts &&
		binding.Fence != ([32]byte{}) &&
		binding.QueryDigest != ([32]byte{}) && binding.CatalogDigest != ([32]byte{}) &&
		binding.ProjectionVersion == kernel.TicketExportProjectionVersion &&
		validInstant(binding.LeaseClaimedAt) && validInstant(binding.LeaseExpiresAt) &&
		binding.LeaseExpiresAt.Sub(binding.LeaseClaimedAt) >= kernel.TicketExportMinimumLease &&
		binding.LeaseExpiresAt.Sub(binding.LeaseClaimedAt) <= kernel.TicketExportMaximumLease &&
		validInstant(binding.JobExpiresAt) &&
		!binding.LeaseExpiresAt.After(binding.JobExpiresAt)
}

func s3ArtifactMaximumBytes(audience kernel.TicketExportAudience) uint64 {
	if audience == kernel.TicketExportAudienceCustomer {
		return kernel.TicketExportCustomerMaximumBytes
	}
	if audience == kernel.TicketExportAudienceOperator {
		return kernel.TicketExportOperatorMaximumBytes
	}
	return 0
}

func s3ArtifactMaximumRows(audience kernel.TicketExportAudience) uint32 {
	if audience == kernel.TicketExportAudienceCustomer {
		return kernel.TicketExportCustomerMaximumRows
	}
	if audience == kernel.TicketExportAudienceOperator {
		return kernel.TicketExportOperatorMaximumRows
	}
	return 0
}

func validS3ArtifactBucket(value string) bool {
	return s3ArtifactBucketPattern.MatchString(value) && !strings.Contains(value, "..") &&
		!strings.Contains(value, ".-") && !strings.Contains(value, "-.") &&
		!ambiguousS3ArtifactAddress(value)
}

func ambiguousS3ArtifactAddress(value string) bool {
	decimalOrDot := true
	for index := range value {
		if value[index] != '.' && (value[index] < '0' || value[index] > '9') {
			decimalOrDot = false
			break
		}
	}
	if decimalOrDot {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) <= 2 || !strings.HasPrefix(label, "0x") {
			continue
		}
		hexadecimal := true
		for index := 2; index < len(label); index++ {
			character := label[index]
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				hexadecimal = false
				break
			}
		}
		if hexadecimal {
			return true
		}
	}
	return false
}

func validExpectedBucketOwner(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 12 {
		return false
	}
	for index := range value {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validS3ArtifactTemporaryDirectory(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) ||
		!filepath.IsAbs(value) || filepath.Clean(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	info, err := os.Lstat(value)
	return err == nil && info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func validS3ArtifactETag(value string) bool {
	if len(value) < 2 || len(value) > 130 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		if value[index] < 0x21 || value[index] > 0x7e || value[index] == '"' || value[index] == '\\' {
			return false
		}
	}
	return true
}

func s3ArtifactNotFound(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	switch apiError.ErrorCode() {
	case "NotFound", "NoSuchKey", "404":
		return true
	default:
		return false
	}
}

var _ ArtifactStore = (*S3ArtifactStore)(nil)
var _ ArtifactReconciler = (*S3ArtifactStore)(nil)
var _ TemporaryArtifact = (*s3TemporaryArtifact)(nil)
