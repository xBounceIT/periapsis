package ticketing

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var numberingTestNow = time.Date(2026, 12, 31, 23, 0, 0, 123_456_000, time.UTC)

func TestNumberingPolicyGrammarAndUTCPreview(t *testing.T) {
	annual := mustNumberingSpec(t, "CASE", "-", NumberingPeriodAnnual, 6, 1)
	if got, err := annual.Render(1, numberingTestNow); err != nil || got != "CASE-2026-000001" {
		t.Fatalf("annual render = %q, %v", got, err)
	}
	if period, err := annual.PeriodKey(numberingTestNow); err != nil || period != 2026 {
		t.Fatalf("annual period = %d, %v", period, err)
	}
	withoutPeriod := mustNumberingSpec(t, "ALT2", "/", NumberingPeriodNone, 4, 42)
	if got, err := withoutPeriod.Render(42, numberingTestNow); err != nil || got != "ALT2/0042" {
		t.Fatalf("lifetime render = %q, %v", got, err)
	}
	if period, err := withoutPeriod.PeriodKey(numberingTestNow); err != nil || period != 0 {
		t.Fatalf("lifetime period = %d, %v", period, err)
	}
	if annual.NamespaceDigest() == withoutPeriod.NamespaceDigest() ||
		annual.NamespaceDigest() == ([32]byte{}) {
		t.Fatal("formatting namespaces are not domain separated")
	}

	for name, input := range map[string]struct {
		prefix    string
		separator string
		period    NumberingPeriod
		width     uint8
		start     uint64
	}{
		"empty prefix":        {"", "-", NumberingPeriodAnnual, 6, 1},
		"lowercase prefix":    {"Case", "-", NumberingPeriodAnnual, 6, 1},
		"separator in prefix": {"CASE-OPS", "-", NumberingPeriodAnnual, 6, 1},
		"unicode confusable":  {"CАSE", "-", NumberingPeriodAnnual, 6, 1},
		"control prefix":      {"CASE\n", "-", NumberingPeriodAnnual, 6, 1},
		"unknown separator":   {"CASE", ":", NumberingPeriodAnnual, 6, 1},
		"wide separator":      {"CASE", "--", NumberingPeriodAnnual, 6, 1},
		"unknown period":      {"CASE", "-", NumberingPeriod(99), 6, 1},
		"width too small":     {"CASE", "-", NumberingPeriodAnnual, 3, 1},
		"width too large":     {"CASE", "-", NumberingPeriodAnnual, 13, 1},
		"zero start":          {"CASE", "-", NumberingPeriodAnnual, 6, 0},
		"start exceeds width": {"CASE", "-", NumberingPeriodAnnual, 4, 10_000},
	} {
		t.Run(name, func(t *testing.T) {
			if spec, err := NewNumberingPolicySpec(
				input.prefix, input.separator, input.period, input.width, input.start,
			); !errors.Is(err, ErrInvalidNumberingPolicy) || spec != (NumberingPolicySpec{}) {
				t.Fatalf("spec = %#v, error = %v", spec, err)
			}
		})
	}

	local := time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("UTC+1", 3600))
	if _, err := annual.Render(1, local); !errors.Is(err, ErrInvalidNumberingAllocation) {
		t.Fatalf("non-UTC render error = %v", err)
	}
	if _, err := annual.Render(1_000_000, numberingTestNow); !errors.Is(err, ErrInvalidNumberingAllocation) {
		t.Fatalf("variable-width render error = %v", err)
	}
}

func TestPolicyReplacementIsAppendOnlyCAS(t *testing.T) {
	current := mustNumberingPolicy(
		t, fixtureID(900), fixtureID(901), AggregateCase, 1,
		mustNumberingSpec(t, "CASE", "-", NumberingPeriodAnnual, 6, 1),
		fixtureID(902), numberingTestNow,
	)
	original := current
	nextSpec := mustNumberingSpec(t, "INC", "/", NumberingPeriodAnnual, 8, 100)
	plan, err := PlanNumberingPolicyReplacement(
		current, 1, fixtureID(903), nextSpec, fixtureID(904), numberingTestNow.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	next := plan.Next()
	if plan.ExpectedVersion() != 1 || next.Version() != 2 || next.VersionID() != fixtureID(903) ||
		next.Tenant() != current.Tenant() || next.Kind() != AggregateCase || next.Spec() != nextSpec {
		t.Fatalf("plan = %#v, next = %#v", plan, next)
	}
	if !SameNumberingPolicy(current, original) {
		t.Fatal("planning mutated the immutable current version")
	}
	if SameNumberingPolicy(current, next) {
		t.Fatal("replacement reused the current immutable version")
	}

	if _, err := PlanNumberingPolicyReplacement(
		current, 2, fixtureID(905), nextSpec, fixtureID(904), numberingTestNow.Add(time.Second),
	); !errors.Is(err, ErrNumberingRevisionConflict) {
		t.Fatalf("stale revision error = %v", err)
	}
	if _, err := PlanNumberingPolicyReplacement(
		current, 1, fixtureID(905), current.Spec(), fixtureID(904), numberingTestNow.Add(time.Second),
	); !errors.Is(err, ErrNumberingNoChange) {
		t.Fatalf("no-change error = %v", err)
	}
	if _, err := PlanNumberingPolicyReplacement(
		current, 1, current.VersionID(), nextSpec, fixtureID(904), numberingTestNow.Add(time.Second),
	); !errors.Is(err, ErrInvalidNumberingPolicy) {
		t.Fatalf("reused version ID error = %v", err)
	}
	if _, err := PlanNumberingPolicyReplacement(
		current, 1, fixtureID(905), nextSpec, fixtureID(904), numberingTestNow.Add(-time.Microsecond),
	); !errors.Is(err, ErrInvalidNumberingPolicy) {
		t.Fatalf("backdated publication error = %v", err)
	}
}

func TestNumberAllocationContinuesNamespacesAndNeverRewinds(t *testing.T) {
	tenantID := fixtureID(910)
	actorID := fixtureID(911)
	annual := mustNumberingPolicy(
		t, fixtureID(912), tenantID, AggregateAlert, 1,
		mustNumberingSpec(t, "ALT", "-", NumberingPeriodAnnual, 6, 1),
		actorID, numberingTestNow.Add(-time.Hour),
	)
	first, err := PlanNumberAllocation(annual, nil, fixtureID(913), fixtureID(914), numberingTestNow)
	if err != nil || !first.Changed() || first.Replayed() || first.Receipt().Number() != "ALT-2026-000001" {
		t.Fatalf("first plan = %#v, error = %v", first, err)
	}
	counter, ok := first.Counter()
	if !ok || counter.NextValue() != 2 || counter.PeriodKey() != 2026 {
		t.Fatalf("counter = %#v, ok = %t", counter, ok)
	}

	// Start is not part of the formatting namespace. Raising it advances the
	// existing namespace, while a later decrease cannot rewind it.
	raisedSpec := mustNumberingSpec(t, "ALT", "-", NumberingPeriodAnnual, 6, 500)
	raisedPlan, err := PlanNumberingPolicyReplacement(
		annual, 1, fixtureID(915), raisedSpec, actorID, numberingTestNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	raised := raisedPlan.Next()
	if raised.NamespaceDigest() != annual.NamespaceDigest() {
		t.Fatal("start change created a reusable formatting namespace")
	}
	jump, err := PlanNumberAllocation(raised, &counter, fixtureID(916), fixtureID(917), numberingTestNow)
	if err != nil || jump.Receipt().Sequence() != 500 || jump.Receipt().Number() != "ALT-2026-000500" {
		t.Fatalf("jump plan = %#v, error = %v", jump, err)
	}
	counter, _ = jump.Counter()

	loweredSpec := mustNumberingSpec(t, "ALT", "-", NumberingPeriodAnnual, 6, 10)
	loweredPlan, err := PlanNumberingPolicyReplacement(
		raised, 2, fixtureID(918), loweredSpec, actorID, numberingTestNow.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validNumberingPolicy(loweredPlan.Next()) {
		t.Fatal("lowered policy is invalid")
	}
	if !validNumberingCounter(counter, loweredPlan.Next(), numberingTestNow.Add(time.Second)) {
		t.Fatal("counter does not continue the unchanged formatting namespace")
	}
	continued, err := PlanNumberAllocation(
		loweredPlan.Next(), &counter, fixtureID(919), fixtureID(920), numberingTestNow.Add(time.Second),
	)
	if err != nil || continued.Receipt().Sequence() != 501 {
		t.Fatalf("continued plan = %#v, error = %v", continued, err)
	}

	// Annual counters reset only at a UTC year boundary and use the active
	// policy's start. A lifetime policy has period key zero across years.
	nextYear := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	reset, err := PlanNumberAllocation(
		loweredPlan.Next(), nil, fixtureID(921), fixtureID(922), nextYear,
	)
	if err != nil || reset.Receipt().Sequence() != 10 || reset.Receipt().Number() != "ALT-2027-000010" {
		t.Fatalf("annual reset = %#v, error = %v", reset, err)
	}
	if _, err := PlanNumberAllocation(loweredPlan.Next(), &counter, fixtureID(923), fixtureID(924), nextYear); !errors.Is(err, ErrInvalidNumberingAllocation) {
		t.Fatalf("wrong-period counter error = %v", err)
	}

	lifetime := mustNumberingPolicy(
		t, fixtureID(925), tenantID, AggregateCase, 1,
		mustNumberingSpec(t, "CASE", "_", NumberingPeriodNone, 6, 1),
		actorID, numberingTestNow.Add(-time.Hour),
	)
	lifeFirst, err := PlanNumberAllocation(lifetime, nil, fixtureID(926), fixtureID(927), numberingTestNow)
	if err != nil {
		t.Fatal(err)
	}
	lifeCounter, _ := lifeFirst.Counter()
	lifeSecond, err := PlanNumberAllocation(lifetime, &lifeCounter, fixtureID(928), fixtureID(929), nextYear)
	if err != nil || lifeSecond.Receipt().Number() != "CASE_000002" || lifeSecond.Receipt().PeriodKey() != 0 {
		t.Fatalf("lifetime continuation = %#v, error = %v", lifeSecond, err)
	}
}

func TestNumberAllocationExhaustionAndReceiptReplay(t *testing.T) {
	policy := mustNumberingPolicy(
		t, fixtureID(930), fixtureID(931), AggregateCase, 1,
		mustNumberingSpec(t, "CASE", "-", NumberingPeriodNone, 4, 9_999),
		fixtureID(932), numberingTestNow.Add(-time.Hour),
	)
	last, err := PlanNumberAllocation(policy, nil, fixtureID(933), fixtureID(934), numberingTestNow)
	if err != nil || last.Receipt().Number() != "CASE-9999" {
		t.Fatalf("last allocation = %#v, error = %v", last, err)
	}
	exhaustedCounter, _ := last.Counter()
	if _, err := PlanNumberAllocation(
		policy, &exhaustedCounter, fixtureID(935), fixtureID(936), numberingTestNow,
	); !errors.Is(err, ErrNumberingSequenceExhausted) {
		t.Fatalf("exhaustion error = %v", err)
	}

	replay, err := ReplayNumberAllocation(
		last.Receipt(), policy.Tenant(), policy.Kind(), fixtureID(934),
	)
	if err != nil || replay.Changed() || !replay.Replayed() ||
		replay.Receipt().ID() != fixtureID(933) {
		t.Fatalf("replay = %#v, error = %v", replay, err)
	}
	if _, ok := replay.Counter(); ok {
		t.Fatal("replay attempted to advance the sequence")
	}
	for name, coordinate := range map[string]struct {
		tenant    EntityID
		kind      AggregateKind
		aggregate EntityID
	}{
		"foreign tenant":      {fixtureID(937), policy.Kind(), fixtureID(934)},
		"different kind":      {policy.Tenant(), AggregateAlert, fixtureID(934)},
		"different aggregate": {policy.Tenant(), policy.Kind(), fixtureID(938)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReplayNumberAllocation(
				last.Receipt(), coordinate.tenant, coordinate.kind, coordinate.aggregate,
			); !errors.Is(err, ErrNumberingReplayConflict) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := RestoreNumberAllocationReceipt(
		policy, fixtureID(939), fixtureID(940), 9_999, "CASE-0001", numberingTestNow,
	); !errors.Is(err, ErrInvalidNumberingAllocation) {
		t.Fatalf("forged receipt error = %v", err)
	}
}

func TestConcurrentReferenceLedgerAllocatesExactlyOncePerAggregate(t *testing.T) {
	policy := mustNumberingPolicy(
		t, fixtureID(950), fixtureID(951), AggregateAlert, 1,
		mustNumberingSpec(t, "ALT", "-", NumberingPeriodAnnual, 6, 1),
		fixtureID(952), numberingTestNow.Add(-time.Hour),
	)
	ledger := newNumberingReferenceLedger(policy)

	const distinct = 128
	sequences := make(chan uint64, distinct)
	errorsSeen := make(chan error, distinct)
	var wait sync.WaitGroup
	for index := range distinct {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			plan, err := ledger.allocate(fixtureID(uint16(1_000+index)), numberingTestNow)
			if err != nil {
				errorsSeen <- err
				return
			}
			if !plan.Changed() || plan.Replayed() {
				errorsSeen <- errors.New("fresh aggregate was not allocated")
				return
			}
			sequences <- plan.Receipt().Sequence()
		}(index)
	}
	wait.Wait()
	close(sequences)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	got := make([]uint64, 0, distinct)
	for sequence := range sequences {
		got = append(got, sequence)
	}
	slices.Sort(got)
	if len(got) != distinct {
		t.Fatalf("allocated %d sequences", len(got))
	}
	for index, sequence := range got {
		if sequence != uint64(index+1) {
			t.Fatalf("sequence[%d] = %d", index, sequence)
		}
	}

	const contenders = 64
	aggregateID := fixtureID(1_500)
	var changed atomic.Uint32
	var replayed atomic.Uint32
	receiptIDs := make(chan EntityID, contenders)
	errorsSeen = make(chan error, contenders)
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			plan, err := ledger.allocate(aggregateID, numberingTestNow.Add(time.Minute))
			if err != nil {
				errorsSeen <- err
				return
			}
			if plan.Changed() {
				changed.Add(1)
			}
			if plan.Replayed() {
				replayed.Add(1)
			}
			receiptIDs <- plan.Receipt().ID()
		}()
	}
	wait.Wait()
	close(receiptIDs)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatal(err)
	}
	if changed.Load() != 1 || replayed.Load() != contenders-1 {
		t.Fatalf("changed = %d, replayed = %d", changed.Load(), replayed.Load())
	}
	var receiptID EntityID
	for candidate := range receiptIDs {
		if receiptID == (EntityID{}) {
			receiptID = candidate
		} else if candidate != receiptID {
			t.Fatalf("aggregate received multiple receipts: %v and %v", receiptID, candidate)
		}
	}
	if ledger.receiptCount() != distinct+1 {
		t.Fatalf("receipt count = %d", ledger.receiptCount())
	}
}

func TestConcurrentPolicyCASPublishesOneImmutableVersion(t *testing.T) {
	current := mustNumberingPolicy(
		t, fixtureID(1_600), fixtureID(1_601), AggregateCase, 1,
		mustNumberingSpec(t, "CASE", "-", NumberingPeriodAnnual, 6, 1),
		fixtureID(1_602), numberingTestNow,
	)
	original := current
	store := &numberingPolicyReferenceStore{current: current}
	const contenders = 32
	var published atomic.Uint32
	var conflicts atomic.Uint32
	var wait sync.WaitGroup
	for index := range contenders {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			spec := mustNumberingSpec(
				t, "CASE", "-", NumberingPeriodAnnual, 6, uint64(index+2),
			)
			err := store.replace(1, fixtureID(uint16(1_700+index)), spec, fixtureID(1_602))
			switch {
			case err == nil:
				published.Add(1)
			case errors.Is(err, ErrNumberingRevisionConflict):
				conflicts.Add(1)
			default:
				t.Errorf("replace error = %v", err)
			}
		}(index)
	}
	wait.Wait()
	if published.Load() != 1 || conflicts.Load() != contenders-1 {
		t.Fatalf("published = %d, conflicts = %d", published.Load(), conflicts.Load())
	}
	if store.snapshot().Version() != 2 || !SameNumberingPolicy(current, original) {
		t.Fatal("CAS did not preserve one immutable predecessor and one successor")
	}
}

type numberingCounterCoordinate struct {
	namespace [32]byte
	period    int
}

type numberingReferenceLedger struct {
	mu       sync.Mutex
	policy   NumberingPolicy
	counters map[numberingCounterCoordinate]NumberingCounter
	receipts map[EntityID]NumberAllocationReceipt
	nextID   uint16
}

func newNumberingReferenceLedger(policy NumberingPolicy) *numberingReferenceLedger {
	return &numberingReferenceLedger{
		policy: policy, counters: make(map[numberingCounterCoordinate]NumberingCounter),
		receipts: make(map[EntityID]NumberAllocationReceipt), nextID: 2_000,
	}
}

func (ledger *numberingReferenceLedger) allocate(
	aggregateID EntityID,
	at time.Time,
) (NumberAllocationPlan, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if receipt, found := ledger.receipts[aggregateID]; found {
		return ReplayNumberAllocation(receipt, ledger.policy.Tenant(), ledger.policy.Kind(), aggregateID)
	}
	period, err := ledger.policy.Spec().PeriodKey(at)
	if err != nil {
		return NumberAllocationPlan{}, err
	}
	coordinate := numberingCounterCoordinate{
		namespace: ledger.policy.NamespaceDigest(), period: period,
	}
	var counter *NumberingCounter
	if stored, found := ledger.counters[coordinate]; found {
		copy := stored
		counter = &copy
	}
	receiptID := fixtureID(ledger.nextID)
	ledger.nextID++
	plan, err := PlanNumberAllocation(ledger.policy, counter, receiptID, aggregateID, at)
	if err != nil {
		return NumberAllocationPlan{}, err
	}
	next, _ := plan.Counter()
	ledger.counters[coordinate] = next
	ledger.receipts[aggregateID] = plan.Receipt()
	return plan, nil
}

func (ledger *numberingReferenceLedger) receiptCount() int {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return len(ledger.receipts)
}

type numberingPolicyReferenceStore struct {
	mu      sync.Mutex
	current NumberingPolicy
}

func (store *numberingPolicyReferenceStore) replace(
	expected uint64,
	versionID EntityID,
	spec NumberingPolicySpec,
	publisher EntityID,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	plan, err := PlanNumberingPolicyReplacement(
		store.current, expected, versionID, spec, publisher, numberingTestNow.Add(time.Second),
	)
	if err != nil {
		return err
	}
	store.current = plan.Next()
	return nil
}

func (store *numberingPolicyReferenceStore) snapshot() NumberingPolicy {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.current
}

func mustNumberingSpec(
	t testing.TB,
	prefix string,
	separator string,
	period NumberingPeriod,
	width uint8,
	start uint64,
) NumberingPolicySpec {
	t.Helper()
	spec, err := NewNumberingPolicySpec(prefix, separator, period, width, start)
	if err != nil {
		t.Fatalf("NewNumberingPolicySpec: %v", err)
	}
	return spec
}

func mustNumberingPolicy(
	t testing.TB,
	versionID EntityID,
	tenant EntityID,
	kind AggregateKind,
	version uint64,
	spec NumberingPolicySpec,
	publishedBy EntityID,
	publishedAt time.Time,
) NumberingPolicy {
	t.Helper()
	policy, err := NewNumberingPolicy(
		versionID, tenant, kind, version, spec, publishedBy, publishedAt,
	)
	if err != nil {
		t.Fatalf("NewNumberingPolicy: %v", err)
	}
	return policy
}

func TestSystemNumberingPolicyPublisherIsExplicitAndVersionOneOnly(t *testing.T) {
	t.Parallel()

	policy, err := RestoreSystemNumberingPolicy(
		fixtureID(220),
		fixtureID(221),
		AggregateAlert,
		mustNumberingSpec(t, "ALT", "-", NumberingPeriodAnnual, 6, 1),
		time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("RestoreSystemNumberingPolicy: %v", err)
	}
	if policy.Publisher().Kind() != NumberingPolicyPublisherSystem {
		t.Fatalf("publisher kind = %v, want system", policy.Publisher().Kind())
	}
	if _, ok := policy.Publisher().MembershipID(); ok {
		t.Fatal("system publisher unexpectedly has a membership")
	}
	if policy.PublishedBy() != (EntityID{}) {
		t.Fatal("legacy PublishedBy accessor leaked a synthetic publisher")
	}
}
