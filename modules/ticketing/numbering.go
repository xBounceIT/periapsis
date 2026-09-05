package ticketing

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	MinimumNumberingWidth = uint8(4)
	MaximumNumberingWidth = uint8(12)
	MaximumPolicyVersion  = uint64(math.MaxInt32)
	minimumNumberingYear  = 2000
	maximumNumberingYear  = 9999
)

var (
	ErrInvalidNumberingPolicy     = errors.New("invalid ticket numbering policy")
	ErrNumberingRevisionConflict  = errors.New("ticket numbering policy revision conflict")
	ErrNumberingNoChange          = errors.New("ticket numbering policy has no change")
	ErrInvalidNumberingAllocation = errors.New("invalid ticket number allocation")
	ErrNumberingSequenceExhausted = errors.New("ticket numbering sequence exhausted")
	ErrNumberingReplayConflict    = errors.New("ticket numbering allocation replay conflict")
)

// NumberingPeriod is deliberately a closed vocabulary. Annual periods always
// use the allocation instant's UTC year; PeriodNone is one lifetime sequence.
type NumberingPeriod uint8

const (
	NumberingPeriodAnnual NumberingPeriod = iota + 1
	NumberingPeriodNone
)

func (period NumberingPeriod) String() string {
	switch period {
	case NumberingPeriodAnnual:
		return "annual"
	case NumberingPeriodNone:
		return "none"
	default:
		return "unknown"
	}
}

func validNumberingPeriod(period NumberingPeriod) bool {
	return period == NumberingPeriodAnnual || period == NumberingPeriodNone
}

// NumberingPolicySpec is a canonical, non-executable formatting grammar. The
// prefix is uppercase ASCII and cannot contain a separator. Width is a fixed
// digit count: a sequence is exhausted before it could grow beyond the width.
// This makes distinct formatting namespaces disjoint and prevents a policy
// change from silently manufacturing duplicate display numbers.
type NumberingPolicySpec struct {
	prefix    string
	separator string
	period    NumberingPeriod
	width     uint8
	start     uint64
}

func NewNumberingPolicySpec(
	prefix string,
	separator string,
	period NumberingPeriod,
	width uint8,
	start uint64,
) (NumberingPolicySpec, error) {
	spec := NumberingPolicySpec{
		prefix: prefix, separator: separator, period: period, width: width, start: start,
	}
	if !validNumberingPolicySpec(spec) {
		return NumberingPolicySpec{}, ErrInvalidNumberingPolicy
	}
	return spec, nil
}

func (spec NumberingPolicySpec) Prefix() string          { return spec.prefix }
func (spec NumberingPolicySpec) Separator() string       { return spec.separator }
func (spec NumberingPolicySpec) Period() NumberingPeriod { return spec.period }
func (spec NumberingPolicySpec) Width() uint8            { return spec.width }
func (spec NumberingPolicySpec) Start() uint64           { return spec.start }

// MaximumSequence is the largest value that still renders to exactly Width
// digits. PostgreSQL bigint safely contains the complete supported range.
func (spec NumberingPolicySpec) MaximumSequence() uint64 {
	if !validNumberingPolicySpec(spec) {
		return 0
	}
	return maximumSequenceForWidth(spec.width)
}

// NamespaceDigest deliberately excludes Start. Re-enabling an old grammar
// therefore continues its durable counter instead of reusing numbers. Start is
// a lower bound: raising it may advance a counter, while lowering it never
// rewinds an existing counter. A fresh annual period begins at the then-current
// policy's Start value.
func (spec NumberingPolicySpec) NamespaceDigest() [sha256.Size]byte {
	if !validNumberingPolicySpec(spec) {
		return [sha256.Size]byte{}
	}
	canonical := "periapsis/ticket-numbering/namespace/v1\x00" +
		spec.prefix + "\x00" + spec.separator + "\x00" + spec.period.String() + "\x00" +
		strconv.FormatUint(uint64(spec.width), 10)
	return sha256.Sum256([]byte(canonical))
}

func (spec NumberingPolicySpec) PeriodKey(at time.Time) (int, error) {
	if !validNumberingPolicySpec(spec) || !validNumberingInstant(at) {
		return 0, ErrInvalidNumberingAllocation
	}
	if spec.period == NumberingPeriodNone {
		return 0, nil
	}
	return at.Year(), nil
}

func (spec NumberingPolicySpec) Render(sequence uint64, at time.Time) (string, error) {
	if !validNumberingPolicySpec(spec) || !validNumberingInstant(at) ||
		sequence < spec.start || sequence > spec.MaximumSequence() {
		return "", ErrInvalidNumberingAllocation
	}
	serial := strconv.FormatUint(sequence, 10)
	serial = strings.Repeat("0", int(spec.width)-len(serial)) + serial
	if spec.period == NumberingPeriodNone {
		return spec.prefix + spec.separator + serial, nil
	}
	return spec.prefix + spec.separator + strconv.Itoa(at.Year()) + spec.separator + serial, nil
}

func validNumberingPolicySpec(spec NumberingPolicySpec) bool {
	if !validNumberingPrefix(spec.prefix) || !validNumberingSeparator(spec.separator) ||
		!validNumberingPeriod(spec.period) || spec.width < MinimumNumberingWidth ||
		spec.width > MaximumNumberingWidth {
		return false
	}
	maximum := maximumSequenceForWidth(spec.width)
	return maximum > 0 && spec.start >= 1 && spec.start <= maximum
}

func validNumberingPrefix(value string) bool {
	if len(value) < 1 || len(value) > 12 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character < 'A' || character > 'Z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validNumberingSeparator(value string) bool {
	return value == "-" || value == "/" || value == "." || value == "_"
}

func maximumSequenceForWidth(width uint8) uint64 {
	if width < MinimumNumberingWidth || width > MaximumNumberingWidth {
		return 0
	}
	maximum := uint64(1)
	for range width {
		maximum *= 10
	}
	return maximum - 1
}

// NumberingPolicy is one immutable tenant-and-kind policy version. Replacing a
// policy appends a new value with a new VersionID; existing tickets and receipts
// remain pinned to the historical value.
type NumberingPolicy struct {
	versionID   EntityID
	tenant      EntityID
	kind        AggregateKind
	version     uint64
	spec        NumberingPolicySpec
	publisher   NumberingPolicyPublisher
	publishedAt time.Time
}

type NumberingPolicyPublisherKind uint8

const (
	NumberingPolicyPublisherSystem NumberingPolicyPublisherKind = iota + 1
	NumberingPolicyPublisherMembership
)

// NumberingPolicyPublisher is a closed provenance union. Version-one defaults
// are installed by the system even for tenants that do not yet have a
// membership; every administrative version has an exact human membership.
type NumberingPolicyPublisher struct {
	kind         NumberingPolicyPublisherKind
	membershipID EntityID
}

func SystemNumberingPolicyPublisher() NumberingPolicyPublisher {
	return NumberingPolicyPublisher{kind: NumberingPolicyPublisherSystem}
}

func MembershipNumberingPolicyPublisher(membershipID EntityID) (NumberingPolicyPublisher, error) {
	if !validEntityID(membershipID) {
		return NumberingPolicyPublisher{}, ErrInvalidNumberingPolicy
	}
	return NumberingPolicyPublisher{
		kind: NumberingPolicyPublisherMembership, membershipID: membershipID,
	}, nil
}

func (publisher NumberingPolicyPublisher) Kind() NumberingPolicyPublisherKind {
	return publisher.kind
}

func (publisher NumberingPolicyPublisher) MembershipID() (EntityID, bool) {
	return publisher.membershipID, publisher.kind == NumberingPolicyPublisherMembership
}

func validNumberingPolicyPublisher(publisher NumberingPolicyPublisher) bool {
	return publisher.kind == NumberingPolicyPublisherSystem && publisher.membershipID == (EntityID{}) ||
		publisher.kind == NumberingPolicyPublisherMembership && validEntityID(publisher.membershipID)
}

func NewNumberingPolicy(
	versionID EntityID,
	tenant EntityID,
	kind AggregateKind,
	version uint64,
	spec NumberingPolicySpec,
	publishedBy EntityID,
	publishedAt time.Time,
) (NumberingPolicy, error) {
	publisher, err := MembershipNumberingPolicyPublisher(publishedBy)
	if err != nil {
		return NumberingPolicy{}, err
	}
	return restoreNumberingPolicy(
		versionID, tenant, kind, version, spec, publisher, publishedAt,
	)
}

// RestoreSystemNumberingPolicy restores the immutable system-authored default.
// System provenance is valid only for version one.
func RestoreSystemNumberingPolicy(
	versionID EntityID,
	tenant EntityID,
	kind AggregateKind,
	spec NumberingPolicySpec,
	publishedAt time.Time,
) (NumberingPolicy, error) {
	return restoreNumberingPolicy(
		versionID, tenant, kind, 1, spec, SystemNumberingPolicyPublisher(), publishedAt,
	)
}

func restoreNumberingPolicy(
	versionID EntityID,
	tenant EntityID,
	kind AggregateKind,
	version uint64,
	spec NumberingPolicySpec,
	publisher NumberingPolicyPublisher,
	publishedAt time.Time,
) (NumberingPolicy, error) {
	policy := NumberingPolicy{
		versionID: versionID, tenant: tenant, kind: kind, version: version, spec: spec,
		publisher: publisher, publishedAt: publishedAt,
	}
	if !validNumberingPolicy(policy) {
		return NumberingPolicy{}, ErrInvalidNumberingPolicy
	}
	return policy, nil
}

func (policy NumberingPolicy) VersionID() EntityID       { return policy.versionID }
func (policy NumberingPolicy) Tenant() EntityID          { return policy.tenant }
func (policy NumberingPolicy) Kind() AggregateKind       { return policy.kind }
func (policy NumberingPolicy) Version() uint64           { return policy.version }
func (policy NumberingPolicy) Spec() NumberingPolicySpec { return policy.spec }
func (policy NumberingPolicy) Publisher() NumberingPolicyPublisher {
	return policy.publisher
}

// PublishedBy returns the human publisher when present. System-authored
// defaults return the zero EntityID; new code should inspect Publisher first.
func (policy NumberingPolicy) PublishedBy() EntityID {
	membershipID, _ := policy.publisher.MembershipID()
	return membershipID
}
func (policy NumberingPolicy) PublishedAt() time.Time { return policy.publishedAt }
func (policy NumberingPolicy) NamespaceDigest() [sha256.Size]byte {
	return policy.spec.NamespaceDigest()
}

func (policy NumberingPolicy) String() string {
	return fmt.Sprintf(
		"NumberingPolicy{kind:%s,version:%d,period:%s,width:%d,format:[REDACTED]}",
		policy.kind, policy.version, policy.spec.period, policy.spec.width,
	)
}

func validNumberingPolicy(policy NumberingPolicy) bool {
	return validEntityID(policy.versionID) && validEntityID(policy.tenant) &&
		validAggregateKind(policy.kind) && policy.version >= 1 &&
		policy.version <= MaximumPolicyVersion && validNumberingPolicySpec(policy.spec) &&
		validNumberingPolicyPublisher(policy.publisher) &&
		(policy.publisher.kind != NumberingPolicyPublisherSystem || policy.version == 1) &&
		validNumberingInstant(policy.publishedAt)
}

func SameNumberingPolicy(left, right NumberingPolicy) bool {
	return validNumberingPolicy(left) && validNumberingPolicy(right) &&
		left.versionID == right.versionID && left.tenant == right.tenant &&
		left.kind == right.kind && left.version == right.version && left.spec == right.spec &&
		left.publisher == right.publisher && left.publishedAt.Equal(right.publishedAt)
}

// NumberingPolicyPlan is a deterministic append-only policy transition. The
// persistence adapter must compare ExpectedVersion, insert Next as a new row,
// and advance the current pointer in one transaction; it must never update an
// existing policy-version row.
type NumberingPolicyPlan struct {
	expectedVersion uint64
	next            NumberingPolicy
}

func (plan NumberingPolicyPlan) ExpectedVersion() uint64 { return plan.expectedVersion }
func (plan NumberingPolicyPlan) Next() NumberingPolicy   { return plan.next }

func PlanNumberingPolicyCreation(
	versionID EntityID,
	tenant EntityID,
	kind AggregateKind,
	spec NumberingPolicySpec,
	publishedBy EntityID,
	publishedAt time.Time,
) (NumberingPolicyPlan, error) {
	next, err := NewNumberingPolicy(versionID, tenant, kind, 1, spec, publishedBy, publishedAt)
	if err != nil {
		return NumberingPolicyPlan{}, err
	}
	return NumberingPolicyPlan{next: next}, nil
}

func PlanNumberingPolicyReplacement(
	current NumberingPolicy,
	expectedVersion uint64,
	nextVersionID EntityID,
	nextSpec NumberingPolicySpec,
	publishedBy EntityID,
	publishedAt time.Time,
) (NumberingPolicyPlan, error) {
	if !validNumberingPolicy(current) || !validNumberingPolicySpec(nextSpec) ||
		!validEntityID(nextVersionID) || nextVersionID == current.versionID ||
		!validEntityID(publishedBy) || !validNumberingInstant(publishedAt) ||
		publishedAt.Before(current.publishedAt) {
		return NumberingPolicyPlan{}, ErrInvalidNumberingPolicy
	}
	if expectedVersion != current.version || current.version == MaximumPolicyVersion {
		return NumberingPolicyPlan{}, ErrNumberingRevisionConflict
	}
	if nextSpec == current.spec {
		return NumberingPolicyPlan{}, ErrNumberingNoChange
	}
	next, err := NewNumberingPolicy(
		nextVersionID, current.tenant, current.kind, current.version+1,
		nextSpec, publishedBy, publishedAt,
	)
	if err != nil {
		return NumberingPolicyPlan{}, err
	}
	return NumberingPolicyPlan{expectedVersion: expectedVersion, next: next}, nil
}

// NumberingCounter is the durable next-value state for one formatting
// namespace and period. Counters are shared by policy versions with the same
// NamespaceDigest so reactivating a historical format cannot reuse a number.
type NumberingCounter struct {
	tenant    EntityID
	kind      AggregateKind
	namespace [sha256.Size]byte
	period    int
	next      uint64
}

func RestoreNumberingCounter(
	policy NumberingPolicy,
	at time.Time,
	next uint64,
) (NumberingCounter, error) {
	period, err := policy.spec.PeriodKey(at)
	if err != nil || !validNumberingPolicy(policy) || next < 1 ||
		next > policy.spec.MaximumSequence()+1 {
		return NumberingCounter{}, ErrInvalidNumberingAllocation
	}
	return NumberingCounter{
		tenant: policy.tenant, kind: policy.kind, namespace: policy.NamespaceDigest(),
		period: period, next: next,
	}, nil
}

func (counter NumberingCounter) Tenant() EntityID                   { return counter.tenant }
func (counter NumberingCounter) Kind() AggregateKind                { return counter.kind }
func (counter NumberingCounter) NamespaceDigest() [sha256.Size]byte { return counter.namespace }
func (counter NumberingCounter) PeriodKey() int                     { return counter.period }
func (counter NumberingCounter) NextValue() uint64                  { return counter.next }

func validNumberingCounter(counter NumberingCounter, policy NumberingPolicy, at time.Time) bool {
	period, err := policy.spec.PeriodKey(at)
	return err == nil && counter.tenant == policy.tenant && counter.kind == policy.kind &&
		counter.namespace == policy.NamespaceDigest() && counter.period == period &&
		counter.next >= 1 && counter.next <= policy.spec.MaximumSequence()+1
}

// NumberAllocationReceipt is immutable proof that one ticket aggregate owns
// one rendered number under an exact historical policy version.
type NumberAllocationReceipt struct {
	id              EntityID
	tenant          EntityID
	kind            AggregateKind
	aggregate       EntityID
	policyVersionID EntityID
	policyVersion   uint64
	namespace       [sha256.Size]byte
	period          int
	sequence        uint64
	number          string
	allocatedAt     time.Time
}

func (receipt NumberAllocationReceipt) ID() EntityID                       { return receipt.id }
func (receipt NumberAllocationReceipt) Tenant() EntityID                   { return receipt.tenant }
func (receipt NumberAllocationReceipt) Kind() AggregateKind                { return receipt.kind }
func (receipt NumberAllocationReceipt) Aggregate() EntityID                { return receipt.aggregate }
func (receipt NumberAllocationReceipt) PolicyVersionID() EntityID          { return receipt.policyVersionID }
func (receipt NumberAllocationReceipt) PolicyVersion() uint64              { return receipt.policyVersion }
func (receipt NumberAllocationReceipt) NamespaceDigest() [sha256.Size]byte { return receipt.namespace }
func (receipt NumberAllocationReceipt) PeriodKey() int                     { return receipt.period }
func (receipt NumberAllocationReceipt) Sequence() uint64                   { return receipt.sequence }
func (receipt NumberAllocationReceipt) Number() string                     { return receipt.number }
func (receipt NumberAllocationReceipt) AllocatedAt() time.Time             { return receipt.allocatedAt }

func (receipt NumberAllocationReceipt) String() string {
	return fmt.Sprintf(
		"NumberAllocationReceipt{kind:%s,policy_version:%d,sequence:%d,number:[REDACTED]}",
		receipt.kind, receipt.policyVersion, receipt.sequence,
	)
}

func RestoreNumberAllocationReceipt(
	policy NumberingPolicy,
	receiptID EntityID,
	aggregateID EntityID,
	sequence uint64,
	number string,
	allocatedAt time.Time,
) (NumberAllocationReceipt, error) {
	period, periodErr := policy.spec.PeriodKey(allocatedAt)
	rendered, renderErr := policy.spec.Render(sequence, allocatedAt)
	if !validNumberingPolicy(policy) || !validEntityID(receiptID) ||
		!validEntityID(aggregateID) || periodErr != nil || renderErr != nil || rendered != number ||
		allocatedAt.Before(policy.publishedAt) {
		return NumberAllocationReceipt{}, ErrInvalidNumberingAllocation
	}
	return NumberAllocationReceipt{
		id: receiptID, tenant: policy.tenant, kind: policy.kind, aggregate: aggregateID,
		policyVersionID: policy.versionID, policyVersion: policy.version,
		namespace: policy.NamespaceDigest(), period: period, sequence: sequence,
		number: number, allocatedAt: allocatedAt,
	}, nil
}

func validNumberAllocationReceipt(receipt NumberAllocationReceipt) bool {
	return validEntityID(receipt.id) && validEntityID(receipt.tenant) &&
		validAggregateKind(receipt.kind) && validEntityID(receipt.aggregate) &&
		validEntityID(receipt.policyVersionID) && receipt.policyVersion >= 1 &&
		receipt.policyVersion <= MaximumPolicyVersion && receipt.namespace != [sha256.Size]byte{} &&
		(receipt.period == 0 || receipt.period >= minimumNumberingYear && receipt.period <= maximumNumberingYear) &&
		receipt.sequence >= 1 && receipt.number != "" && len(receipt.number) <= 42 &&
		validNumberingInstant(receipt.allocatedAt)
}

// NumberAllocationPlan either advances one namespace counter and creates an
// immutable receipt, or returns an existing exact aggregate receipt as a replay.
type NumberAllocationPlan struct {
	receipt  NumberAllocationReceipt
	counter  NumberingCounter
	changed  bool
	replayed bool
}

func (plan NumberAllocationPlan) Receipt() NumberAllocationReceipt { return plan.receipt }
func (plan NumberAllocationPlan) Counter() (NumberingCounter, bool) {
	return plan.counter, plan.changed
}
func (plan NumberAllocationPlan) Changed() bool  { return plan.changed }
func (plan NumberAllocationPlan) Replayed() bool { return plan.replayed }

// ReplayNumberAllocation validates the lookup result for an exact aggregate
// coordinate. The original receipt remains authoritative even when the active
// policy or the retry timestamp has changed.
func ReplayNumberAllocation(
	receipt NumberAllocationReceipt,
	tenant EntityID,
	kind AggregateKind,
	aggregateID EntityID,
) (NumberAllocationPlan, error) {
	if !validNumberAllocationReceipt(receipt) || !validEntityID(tenant) ||
		!validAggregateKind(kind) || !validEntityID(aggregateID) {
		return NumberAllocationPlan{}, ErrInvalidNumberingAllocation
	}
	if receipt.tenant != tenant || receipt.kind != kind || receipt.aggregate != aggregateID {
		return NumberAllocationPlan{}, ErrNumberingReplayConflict
	}
	return NumberAllocationPlan{receipt: receipt, replayed: true}, nil
}

// PlanNumberAllocation is the pure new-allocation transition. The caller must
// first look up a receipt by the exact tenant/kind/aggregate coordinate. A
// production adapter serializes on the counter coordinate and protects the
// receipt coordinate with a unique constraint in the same ticket transaction.
func PlanNumberAllocation(
	policy NumberingPolicy,
	counter *NumberingCounter,
	receiptID EntityID,
	aggregateID EntityID,
	allocatedAt time.Time,
) (NumberAllocationPlan, error) {
	if !validNumberingPolicy(policy) || !validEntityID(receiptID) ||
		!validEntityID(aggregateID) || !validNumberingInstant(allocatedAt) ||
		allocatedAt.Before(policy.publishedAt) {
		return NumberAllocationPlan{}, ErrInvalidNumberingAllocation
	}
	next := policy.spec.start
	if counter != nil {
		if !validNumberingCounter(*counter, policy, allocatedAt) {
			return NumberAllocationPlan{}, ErrInvalidNumberingAllocation
		}
		if counter.next > next {
			next = counter.next
		}
	}
	if next > policy.spec.MaximumSequence() {
		return NumberAllocationPlan{}, ErrNumberingSequenceExhausted
	}
	number, err := policy.spec.Render(next, allocatedAt)
	if err != nil {
		return NumberAllocationPlan{}, err
	}
	receipt, err := RestoreNumberAllocationReceipt(
		policy, receiptID, aggregateID, next, number, allocatedAt,
	)
	if err != nil {
		return NumberAllocationPlan{}, err
	}
	period, _ := policy.spec.PeriodKey(allocatedAt)
	nextCounter := NumberingCounter{
		tenant: policy.tenant, kind: policy.kind, namespace: policy.NamespaceDigest(),
		period: period, next: next + 1,
	}
	return NumberAllocationPlan{
		receipt: receipt, counter: nextCounter, changed: true,
	}, nil
}

func validNumberingInstant(value time.Time) bool {
	return validInstant(value) && value.Year() >= minimumNumberingYear &&
		value.Year() <= maximumNumberingYear
}
