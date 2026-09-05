package dfir

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func TestAlertInvestigationWorkspaceRequiresExactOperatorCapabilities(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(1), testEntityID(t, 2)
	actor := testActor(tenantID, PrincipalHuman)
	want := map[Capability]int{
		CapabilityEvidenceRead: 0, CapabilityTaskRead: 0, CapabilityRelationshipRead: 0,
	}
	workspace := validAlertInvestigationWorkspaceFixture(t, tenantID, alertID)
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: func(_ context.Context, got Actor, gotTenant uuid.UUID, capability Capability, scope AlertResourceScope) (Access, error) {
			if got != actor || gotTenant != tenantID || scope.AlertID != alertID {
				return Access{}, fmt.Errorf("wrong exact scope")
			}
			if _, exists := want[capability]; !exists {
				return Access{}, fmt.Errorf("unexpected capability %q", capability)
			}
			want[capability]++
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeOperatorTeam}, nil
		},
		loadWorkspace: func(_ context.Context, got Actor, gotTenant uuid.UUID, gotAlert kernel.EntityID, access WorkspaceAccess) (AlertInvestigationWorkspace, error) {
			if got != actor || gotTenant != tenantID || gotAlert != alertID || len(access) != len(want) {
				return AlertInvestigationWorkspace{}, fmt.Errorf("workspace load lost authority")
			}
			return workspace, nil
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(20))
	result, err := service.Workspace(context.Background(), actor, tenantID, alertID)
	if err != nil || len(result.Evidence) != 1 || len(result.Tasks) != 1 || len(result.Relationships) != 1 {
		t.Fatalf("Workspace() = (%#v, %v)", result, err)
	}
	for capability, calls := range want {
		if calls != 1 {
			t.Fatalf("capability %q resolved %d times", capability, calls)
		}
	}

	resolves := 0
	repository.resolveAlertAccess = func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
		resolves++
		return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
	}
	if _, err := service.Workspace(
		context.Background(), testActor(tenantID, PrincipalCustomer), tenantID, alertID,
	); !errors.Is(err, ErrForbidden) || resolves != 0 {
		t.Fatalf("customer workspace = (%v, resolves=%d)", err, resolves)
	}

	foreign := workspace
	foreign.Evidence = []kernel.AlertEvidence{validAlertEvidenceFixture(t, testUUID(3), alertID, 4)}
	repository.loadWorkspace = func(context.Context, Actor, uuid.UUID, kernel.EntityID, WorkspaceAccess) (AlertInvestigationWorkspace, error) {
		return foreign, nil
	}
	if _, err := service.Workspace(context.Background(), actor, tenantID, alertID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign workspace error = %v", err)
	}
}

func TestAlertEvidenceCollectionBindsVerifiedStorageAndAtomicEffects(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(10), testEntityID(t, 11)
	actor := testActor(tenantID, PrincipalHuman)
	storage := availableStorageObject(t, tenantID, 12, testTime(0))
	command := validAlertEvidenceCollectCommand(t, alertID, storage.ID(), 13)
	commits, effects := 0, 0
	storageForCommit := storage
	var receiptKey, receiptRequest [32]byte
	var storedEvidence kernel.AlertEvidence
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityEvidenceManage),
		commitEvidence: func(_ context.Context, write AlertEvidenceCreateWrite) (MutationResult[kernel.AlertEvidence], error) {
			commits++
			assertAlertMutationContract(t, write.Contract, actor, alertID, CapabilityEvidenceManage, operationAlertEvidenceCreate)
			if receiptKey != ([32]byte{}) && write.Contract.Command.KeyDigest == receiptKey {
				if write.Contract.Command.RequestDigest != receiptRequest {
					return MutationResult[kernel.AlertEvidence]{}, ErrRepositoryConflict
				}
				return MutationResult[kernel.AlertEvidence]{Resource: storedEvidence, Replayed: true}, nil
			}
			if write.StorageObjectID != storage.ID() || write.Build == nil {
				return MutationResult[kernel.AlertEvidence]{}, fmt.Errorf("evidence plan lost storage identity or callback")
			}
			evidence, buildErr := write.Build(storageForCommit)
			if buildErr != nil {
				return MutationResult[kernel.AlertEvidence]{}, buildErr
			}
			if evidence.ContentSHA256() != storageForCommit.ContentSHA256() ||
				evidence.CollectedBy().String() != actor.MembershipID.String() {
				return MutationResult[kernel.AlertEvidence]{}, fmt.Errorf("evidence was not server-bound to storage and actor")
			}
			if events := evidence.CustodyEvents(); len(events) != 1 ||
				events[0].ActorID().String() != actor.UserID.String() {
				return MutationResult[kernel.AlertEvidence]{}, fmt.Errorf("initial custody actor was not bound to the user")
			}
			effects++
			receiptKey, receiptRequest = write.Contract.Command.KeyDigest, write.Contract.Command.RequestDigest
			storedEvidence = evidence
			return MutationResult[kernel.AlertEvidence]{Resource: evidence}, nil
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(20))
	result, err := service.CollectEvidence(context.Background(), actor, tenantID, command)
	if err != nil || result.Resource.AlertID() != alertID || !result.Resource.VerifyCustodyChain() || commits != 1 || effects != 1 {
		t.Fatalf("CollectEvidence() = (%v, commits=%d, effects=%d, %v)", result.Resource, commits, effects, err)
	}
	storageForCommit = kernel.StorageObject{}
	replay, err := service.CollectEvidence(context.Background(), actor, tenantID, command)
	if err != nil || !replay.Replayed || commits != 2 || effects != 1 {
		t.Fatalf("evidence replay after storage drift = (replayed=%t, commits=%d, effects=%d, %v)", replay.Replayed, commits, effects, err)
	}

	badStorage := storage.Snapshot()
	badStorage.ObjectKey = tenantID.String() + "/different"
	mismatched, restoreErr := kernel.RestoreStorageObject(badStorage)
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	storageForCommit = mismatched
	command.Envelope = testEnvelope(16)
	if _, err := service.CollectEvidence(context.Background(), actor, tenantID, command); !errors.Is(err, ErrUnavailable) || commits != 3 || effects != 1 {
		t.Fatalf("mismatched storage = (%v, commits=%d, effects=%d)", err, commits, effects)
	}

	storageForCommit = storage
	command.Envelope = testEnvelope(17)
	command.Title = "hidden\u202eexe"
	if _, err := service.CollectEvidence(context.Background(), actor, tenantID, command); !errors.Is(err, ErrInvalidInput) || commits != 3 || effects != 1 {
		t.Fatalf("bidi title = (%v, commits=%d, effects=%d)", err, commits, effects)
	}
}

func TestAlertEvidenceCustodyCallbackPinsActorCASAndReplayShape(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(20), testEntityID(t, 21)
	actor := testActor(tenantID, PrincipalHuman)
	current := validAlertEvidenceFixture(t, tenantID, alertID, 22)
	command := AlertCustodyCommand{
		AlertID: alertID, EvidenceID: current.ID(), ExpectedVersion: 1,
		EventID: testEntityID(t, 26), Action: kernel.CustodyAccessed, Reason: "forensic review",
		Envelope: testEnvelope(27),
	}
	mutations := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityEvidenceManage),
		mutateEvidence: func(_ context.Context, write AlertEvidenceMutationWrite) (MutationResult[kernel.AlertEvidence], error) {
			mutations++
			assertAlertMutationContract(t, write.Contract, actor, alertID, CapabilityEvidenceManage, operationAlertEvidenceCustody)
			if write.Contract.AuditReason != command.Reason {
				return MutationResult[kernel.AlertEvidence]{}, fmt.Errorf("custody audit reason was not preserved")
			}
			if write.EvidenceID != current.ID() || write.ExpectedVersion != 1 || write.Apply == nil {
				return MutationResult[kernel.AlertEvidence]{}, fmt.Errorf("invalid evidence mutation plan")
			}
			updated, err := write.Apply(current)
			return MutationResult[kernel.AlertEvidence]{Resource: updated}, err
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(30))
	result, err := service.AppendCustody(context.Background(), actor, tenantID, command)
	if err != nil || result.Resource.Version() != 2 || mutations != 1 {
		t.Fatalf("AppendCustody() = (%v, mutations=%d, %v)", result.Resource, mutations, err)
	}
	last := result.Resource.CustodyEvents()[1]
	if last.ActorID().String() != actor.UserID.String() || last.OccurredAt() != testTime(30) {
		t.Fatal("custody event trusted a caller actor or timestamp")
	}

	bad := command
	bad.NextScanState = kernel.ScanScanning
	if _, err := service.AppendCustody(context.Background(), actor, tenantID, bad); !errors.Is(err, ErrInvalidInput) || mutations != 1 {
		t.Fatalf("ambiguous custody command = (%v, mutations=%d)", err, mutations)
	}
	bad = command
	bad.ExpectedVersion = uint64(^uint64(0) >> 1)
	if _, err := service.AppendCustody(context.Background(), actor, tenantID, bad); !errors.Is(err, ErrInvalidInput) || mutations != 1 {
		t.Fatalf("overflow custody command = (%v, mutations=%d)", err, mutations)
	}
	bad = command
	bad.ExpectedVersion = kernel.MaximumCustodyEvents
	if _, err := service.AppendCustody(context.Background(), actor, tenantID, bad); !errors.Is(err, ErrInvalidInput) || mutations != 1 {
		t.Fatalf("oversized custody command = (%v, mutations=%d)", err, mutations)
	}
}

func TestAlertTaskMutationsCoverAssignmentDueChecklistAndLifecycle(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(30), testEntityID(t, 31)
	actor := testActor(tenantID, PrincipalHuman)
	current := validAlertTaskFixture(t, tenantID, alertID, 32)
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
	}
	repository.mutateTask = func(_ context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
		updated, err := write.Apply(current)
		if err == nil {
			current = updated
		}
		return MutationResult[kernel.AlertTask]{Resource: updated}, err
	}
	service := mustAlertInvestigationService(t, repository, testTime(40))
	team, assignee := testEntityID(t, 33), testEntityID(t, 34)
	result, err := service.AssignTask(context.Background(), actor, tenantID, AlertTaskAssignmentCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 1,
		OperatorTeamID: &team, AssigneeID: &assignee, Envelope: testEnvelope(35),
	})
	if err != nil || result.Resource.Version() != 2 || result.Resource.AssigneeID() == nil {
		t.Fatalf("AssignTask() = (%v, %v)", result.Resource, err)
	}
	due := testTime(40).Add(24 * time.Hour)
	result, err = service.RescheduleTask(context.Background(), actor, tenantID, AlertTaskDueDateCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 2, DueAt: &due, Envelope: testEnvelope(36),
	})
	if err != nil || result.Resource.Version() != 3 || result.Resource.DueAt() == nil {
		t.Fatalf("RescheduleTask() = (%v, %v)", result.Resource, err)
	}
	item := AlertChecklistItemIntent{ID: testEntityID(t, 37), Title: "Acquire memory", Completed: true}
	result, err = service.ReplaceTaskChecklist(context.Background(), actor, tenantID, AlertTaskChecklistCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 3,
		Checklist: []AlertChecklistItemIntent{item}, Envelope: testEnvelope(38),
	})
	if err != nil || result.Resource.Version() != 4 || len(result.Resource.Checklist()) != 1 {
		t.Fatalf("ReplaceTaskChecklist() = (%v, %v)", result.Resource, err)
	}
	completed := result.Resource.Checklist()[0]
	if completed.CompletedAt() == nil || *completed.CompletedAt() != testTime(40) ||
		completed.CompletedBy() == nil || completed.CompletedBy().String() != actor.UserID.String() {
		t.Fatal("checklist completion trusted caller-supplied provenance")
	}
	preservedAt, preservedBy := *completed.CompletedAt(), *completed.CompletedBy()
	item = AlertChecklistItemIntent{ID: completed.ID(), Title: completed.Title(), Completed: true}
	result, err = service.ReplaceTaskChecklist(context.Background(), actor, tenantID, AlertTaskChecklistCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 4,
		Checklist: []AlertChecklistItemIntent{item}, Envelope: testEnvelope(39),
	})
	if err != nil || result.Resource.Version() != 5 || len(result.Resource.Checklist()) != 1 {
		t.Fatalf("second ReplaceTaskChecklist() = (%v, %v)", result.Resource, err)
	}
	completed = result.Resource.Checklist()[0]
	if completed.CompletedAt() == nil ||
		*completed.CompletedAt() != preservedAt || completed.CompletedBy() == nil || *completed.CompletedBy() != preservedBy {
		t.Fatalf("completed checklist provenance was not preserved: (%v, %v)", result.Resource, err)
	}
	commentID := testEntityID(t, 43)
	result, err = service.ReplaceTaskComments(context.Background(), actor, tenantID, AlertTaskCommentsCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 5,
		CommentIDs: []kernel.EntityID{commentID}, Envelope: testEnvelope(44),
	})
	if err != nil || result.Resource.Version() != 6 ||
		len(result.Resource.CommentIDs()) != 1 || result.Resource.CommentIDs()[0] != commentID {
		t.Fatalf("ReplaceTaskComments() = (%v, %v)", result.Resource, err)
	}
	result, err = service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 6,
		Target: kernel.TaskInProgress, Reason: "begin work", Envelope: testEnvelope(40),
	})
	if err != nil || result.Resource.Version() != 7 || result.Resource.Status() != kernel.TaskInProgress {
		t.Fatalf("TransitionTask() = (%v, %v)", result.Resource, err)
	}
	result, err = service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 7,
		Target: kernel.TaskDone, Reason: "work completed", CompletionData: []byte(`{"verified":true}`),
		Envelope: testEnvelope(42),
	})
	if err != nil || result.Resource.Version() != 8 || result.Resource.Status() != kernel.TaskDone ||
		result.Resource.CompletedBy() == nil || result.Resource.CompletedBy().String() != actor.UserID.String() {
		t.Fatalf("completed task user attribution = (%v, %v)", result.Resource, err)
	}

	if _, err := service.RescheduleTask(context.Background(), actor, tenantID, AlertTaskDueDateCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 4,
		DueAt: &due, Envelope: testEnvelope(41),
	}); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale task mutation error = %v", err)
	}
}

func TestAlertTaskDetailsMutationUsesGenericCASAndSupportsSLAClear(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(130), testEntityID(t, 131)
	actor := testActor(tenantID, PrincipalHuman)
	current := validAlertTaskFixture(t, tenantID, alertID, 132)
	sla := testEntityID(t, 133)
	mutations := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
	}
	repository.mutateTask = func(_ context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
		mutations++
		assertAlertMutationContract(
			t, write.Contract, actor, alertID, CapabilityTaskManage, operationAlertTaskReplaceDetails,
		)
		updated, err := write.Apply(current)
		if err == nil {
			current = updated
		}
		return MutationResult[kernel.AlertTask]{Resource: updated}, err
	}
	service := mustAlertInvestigationService(t, repository, testTime(140))

	result, err := service.ReplaceTaskDetails(context.Background(), actor, tenantID, AlertTaskDetailsCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 1,
		Title: "Contain affected endpoint", Description: "Revised containment instructions",
		Priority: kernel.TaskPriorityUrgent, SLAInstanceID: &sla, Envelope: testEnvelope(134),
	})
	if err != nil || result.Resource.Version() != 2 || result.Resource.Title() != "Contain affected endpoint" ||
		result.Resource.SLAInstanceID() == nil || *result.Resource.SLAInstanceID() != sla {
		t.Fatalf("ReplaceTaskDetails(set SLA) = (%v, %v)", result.Resource, err)
	}

	result, err = service.ReplaceTaskDetails(context.Background(), actor, tenantID, AlertTaskDetailsCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 2,
		Title: "Contain affected endpoint", Description: "Revised containment instructions",
		Priority: kernel.TaskPriorityHigh, Envelope: testEnvelope(135),
	})
	if err != nil || result.Resource.Version() != 3 || result.Resource.Priority() != kernel.TaskPriorityHigh ||
		result.Resource.SLAInstanceID() != nil || mutations != 2 {
		t.Fatalf("ReplaceTaskDetails(clear SLA) = (%v, mutations=%d, %v)", result.Resource, mutations, err)
	}

	_, err = service.ReplaceTaskDetails(context.Background(), actor, tenantID, AlertTaskDetailsCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: kernel.MaximumAlertResourceVersion,
		Title: "Contain affected endpoint", Description: "Revised containment instructions",
		Priority: kernel.TaskPriorityHigh, Envelope: testEnvelope(136),
	})
	if !errors.Is(err, ErrInvalidInput) || mutations != 2 {
		t.Fatalf("terminal details mutation = (%v, mutations=%d)", err, mutations)
	}
}

func TestAlertTaskCreatePinsServerTimeAndValidatesReplayWithoutTimeDrift(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(41), testEntityID(t, 42)
	actor := testActor(tenantID, PrincipalHuman)
	now := testTime(50)
	command := AlertTaskCreateCommand{
		AlertID: alertID, Input: validAlertTaskDraft(t, 43), Envelope: testEnvelope(44),
	}
	var stored kernel.AlertTask
	var requestDigest [32]byte
	var completedStored kernel.AlertTask
	var completedRequestDigest [32]byte
	commits := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
		commitTask: func(_ context.Context, write AlertTaskCreateWrite) (MutationResult[kernel.AlertTask], error) {
			commits++
			assertAlertMutationContract(t, write.Contract, actor, alertID, CapabilityTaskManage, operationAlertTaskCreate)
			if commits == 1 {
				stored = write.Task
				requestDigest = write.Contract.Command.RequestDigest
				return MutationResult[kernel.AlertTask]{Resource: stored}, nil
			}
			if commits == 2 {
				if write.Contract.Command.RequestDigest != requestDigest {
					return MutationResult[kernel.AlertTask]{}, fmt.Errorf("server time changed the replay digest")
				}
				return MutationResult[kernel.AlertTask]{Resource: stored, Replayed: true}, nil
			}
			if commits == 3 {
				completedStored = write.Task
				completedRequestDigest = write.Contract.Command.RequestDigest
				return MutationResult[kernel.AlertTask]{Resource: completedStored}, nil
			}
			if commits == 4 {
				if write.Contract.Command.RequestDigest != completedRequestDigest {
					return MutationResult[kernel.AlertTask]{}, fmt.Errorf("server checklist provenance changed the replay digest")
				}
				return MutationResult[kernel.AlertTask]{Resource: completedStored, Replayed: true}, nil
			}
			return MutationResult[kernel.AlertTask]{Resource: write.Task}, nil
		},
	}
	service, err := NewAlertInvestigationService(repository, AlertInvestigationServiceConfig{
		Bucket: "periapsis-evidence", Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateTask(context.Background(), actor, tenantID, command)
	if err != nil || first.Replayed || first.Resource.CreatedAt() != now {
		t.Fatalf("first create = (%v, replay=%t, %v)", first.Resource, first.Replayed, err)
	}
	now = testTime(60)
	replay, err := service.CreateTask(context.Background(), actor, tenantID, command)
	if err != nil || !replay.Replayed || replay.Resource.CreatedAt() != testTime(50) || commits != 2 {
		t.Fatalf("replayed create = (%v, replay=%t, commits=%d, %v)", replay.Resource, replay.Replayed, commits, err)
	}

	invalid := command
	invalid.Envelope = testEnvelope(45)
	invalid.Input.Checklist = []AlertChecklistItemIntent{{
		ID: testEntityID(t, 47), Title: "Already completed", Completed: true,
	}}
	result, err := service.CreateTask(context.Background(), actor, tenantID, invalid)
	if err != nil || commits != 3 ||
		len(result.Resource.Checklist()) != 1 || result.Resource.Checklist()[0].CompletedBy() == nil ||
		result.Resource.Checklist()[0].CompletedBy().String() != actor.UserID.String() {
		t.Fatalf("completed checklist on task create = (%v, commits=%d, resource=%v)", err, commits, result.Resource)
	}
	completedAt := result.Resource.Checklist()[0].CompletedAt()
	now = testTime(70)
	result, err = service.CreateTask(context.Background(), actor, tenantID, invalid)
	if err != nil || !result.Replayed || commits != 4 || result.Resource.Checklist()[0].CompletedAt() == nil ||
		completedAt == nil || *result.Resource.Checklist()[0].CompletedAt() != *completedAt {
		t.Fatalf("completed checklist replay = (%v, replay=%t, commits=%d, resource=%v)", err, result.Replayed, commits, result.Resource)
	}
	invalid = command
	invalid.Envelope = testEnvelope(46)
	invalid.Input.Title = "spoof\u2067task"
	if _, err := service.CreateTask(context.Background(), actor, tenantID, invalid); !errors.Is(err, ErrInvalidInput) || commits != 4 {
		t.Fatalf("unsafe task create = (%v, commits=%d)", err, commits)
	}
}

func TestAlertMutationRejectsUnsafeAuditTextBeforeRepository(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(47), testEntityID(t, 48)
	actor := testActor(tenantID, PrincipalHuman)
	for name, userAgent := range map[string]string{
		"invalid UTF-8":  string([]byte{0xff}),
		"C1 control":     "browser\u0085suffix",
		"bidi mark":      "browser\u200e",
		"line separator": "browser\u2028suffix",
	} {
		t.Run(name, func(t *testing.T) {
			resolves := 0
			repository := &alertInvestigationRepositoryStub{
				resolveAlertAccess: func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
					resolves++
					return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
				},
			}
			service := mustAlertInvestigationService(t, repository, testTime(60))
			command := AlertTaskCreateCommand{
				AlertID: alertID, Input: validAlertTaskDraft(t, 49), Envelope: testEnvelope(50),
			}
			command.Envelope.Audit.UserAgent = userAgent
			if _, err := service.CreateTask(context.Background(), actor, tenantID, command); !errors.Is(err, ErrInvalidInput) || resolves != 0 {
				t.Fatalf("unsafe audit text = (%v, resolves=%d)", err, resolves)
			}
		})
	}

	resolves := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
			resolves++
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(60))
	command := AlertTaskCreateCommand{
		AlertID: alertID, Input: validAlertTaskDraft(t, 49), Envelope: testEnvelope(51),
	}
	command.Envelope.Audit.AuthenticationMethod = "totp"
	if _, err := service.CreateTask(context.Background(), actor, tenantID, command); !errors.Is(err, ErrInvalidInput) || resolves != 0 {
		t.Fatalf("forged audit authentication method = (%v, resolves=%d)", err, resolves)
	}
}

func TestAlertMutationRejectsInvalidServerClockBeforeReceiptReplay(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(48), testEntityID(t, 49)
	actor := testActor(tenantID, PrincipalHuman)
	initial := validAlertTaskFixture(t, tenantID, alertID, 50)
	actorID, err := alertActorUserEntity(actor)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := initial.Transition(kernel.TaskTransitionInput{
		ExpectedVersion: 1, Target: kernel.TaskInProgress, ActorID: actorID,
		OccurredAt: testTime(60), Reason: "start investigation",
	})
	if err != nil {
		t.Fatal(err)
	}
	mutations := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
		mutateTask: func(context.Context, AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
			mutations++
			return MutationResult[kernel.AlertTask]{Resource: stored, Replayed: true}, nil
		},
	}
	service, err := NewAlertInvestigationService(repository, AlertInvestigationServiceConfig{
		Bucket: "periapsis-evidence", Clock: func() time.Time { return time.Time{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: "start investigation", Envelope: testEnvelope(52),
	})
	if !errors.Is(err, ErrUnavailable) || mutations != 0 {
		t.Fatalf("invalid clock replay = (%v, mutations=%d)", err, mutations)
	}
}

func TestAlertMutationsValidateTemporalAndTransitionIntentBeforeReplay(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(49), testEntityID(t, 50)
	actor := testActor(tenantID, PrincipalHuman)
	initial := validAlertTaskFixture(t, tenantID, alertID, 51)
	due := testTime(80)
	stored, err := initial.Reschedule(1, &due, testTime(70))
	if err != nil {
		t.Fatal(err)
	}
	mutations := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
		mutateTask: func(context.Context, AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
			mutations++
			return MutationResult[kernel.AlertTask]{Resource: stored, Replayed: true}, nil
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(70))
	zeroOffsetAlias := due.In(time.FixedZone("zero-offset-alias", 0))
	if _, err := service.RescheduleTask(context.Background(), actor, tenantID, AlertTaskDueDateCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		DueAt: &zeroOffsetAlias, Envelope: testEnvelope(53),
	}); !errors.Is(err, ErrInvalidInput) || mutations != 0 {
		t.Fatalf("non-canonical due-date replay = (%v, mutations=%d)", err, mutations)
	}

	if _, err := service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: string([]byte{0xff}), Envelope: testEnvelope(54),
	}); !errors.Is(err, ErrInvalidInput) || mutations != 0 {
		t.Fatalf("invalid UTF-8 transition replay = (%v, mutations=%d)", err, mutations)
	}

	oversized := []byte(`{"proof": "` + strings.Repeat(" ", 64*1024) + `"}`)
	if _, err := service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: "start investigation", CompletionData: oversized,
		Envelope: testEnvelope(55),
	}); !errors.Is(err, ErrInvalidInput) || mutations != 0 {
		t.Fatalf("oversized transition replay = (%v, mutations=%d)", err, mutations)
	}

	assignee := testEntityID(t, 58)
	if _, err := service.AssignTask(context.Background(), actor, tenantID, AlertTaskAssignmentCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		AssigneeID: &assignee, Envelope: testEnvelope(59),
	}); !errors.Is(err, ErrInvalidInput) || mutations != 0 {
		t.Fatalf("assignee without team replay = (%v, mutations=%d)", err, mutations)
	}
	lineBreakingItem := AlertChecklistItemIntent{ID: testEntityID(t, 59), Title: "split\u2028checklist item"}
	if _, err := service.ReplaceTaskChecklist(context.Background(), actor, tenantID, AlertTaskChecklistCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		Checklist: []AlertChecklistItemIntent{lineBreakingItem}, Envelope: testEnvelope(60),
	}); !errors.Is(err, ErrInvalidInput) || mutations != 0 {
		t.Fatalf("line-breaking checklist replay = (%v, mutations=%d)", err, mutations)
	}
	if _, err := service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: kernel.MaximumAlertResourceVersion,
		Target: kernel.TaskInProgress, Reason: "start investigation", Envelope: testEnvelope(61),
	}); !errors.Is(err, ErrInvalidInput) || mutations != 0 {
		t.Fatalf("non-JSON-safe task CAS replay = (%v, mutations=%d)", err, mutations)
	}

	storage := availableStorageObject(t, tenantID, 52, testTime(0))
	collect := validAlertEvidenceCollectCommand(t, alertID, storage.ID(), 56)
	collect.CollectedAt = collect.CollectedAt.In(time.FixedZone("zero-offset-alias", 0))
	commits := 0
	repository.resolveAlertAccess = allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityEvidenceManage)
	repository.commitEvidence = func(context.Context, AlertEvidenceCreateWrite) (MutationResult[kernel.AlertEvidence], error) {
		commits++
		return MutationResult[kernel.AlertEvidence]{}, nil
	}
	if _, err := service.CollectEvidence(context.Background(), actor, tenantID, collect); !errors.Is(err, ErrInvalidInput) || commits != 0 {
		t.Fatalf("non-canonical collection time = (%v, commits=%d)", err, commits)
	}
	collect = validAlertEvidenceCollectCommand(t, alertID, storage.ID(), 57)
	collect.CollectedAt = testTime(71)
	if _, err := service.CollectEvidence(context.Background(), actor, tenantID, collect); !errors.Is(err, ErrInvalidInput) || commits != 0 {
		t.Fatalf("future collection time = (%v, commits=%d)", err, commits)
	}

	custodyMutations := 0
	repository.mutateEvidence = func(context.Context, AlertEvidenceMutationWrite) (MutationResult[kernel.AlertEvidence], error) {
		custodyMutations++
		return MutationResult[kernel.AlertEvidence]{}, nil
	}
	if _, err := service.AppendCustody(context.Background(), actor, tenantID, AlertCustodyCommand{
		AlertID: alertID, EvidenceID: testEntityID(t, 61), ExpectedVersion: 1,
		EventID: testEntityID(t, 62), Action: kernel.CustodyScanStateChanged,
		NextScanState: kernel.ScanState("future_state"), Reason: "scanner update", Envelope: testEnvelope(63),
	}); !errors.Is(err, ErrInvalidInput) || custodyMutations != 0 {
		t.Fatalf("unknown scan state replay = (%v, mutations=%d)", err, custodyMutations)
	}
}

func TestAlertFreshMutationsRejectRegressedServerClockAsUnavailable(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(52), testEntityID(t, 53)
	actor := testActor(tenantID, PrincipalHuman)
	serverNow := testTime(5)

	task := validAlertTaskFixture(t, tenantID, alertID, 54)
	taskCalls := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
		mutateTask: func(_ context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
			taskCalls++
			_, err := write.Apply(task)
			return MutationResult[kernel.AlertTask]{}, err
		},
	}
	service := mustAlertInvestigationService(t, repository, serverNow)
	if _, err := service.TransitionTask(context.Background(), actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: task.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: "start", Envelope: testEnvelope(58),
	}); !errors.Is(err, ErrUnavailable) || taskCalls != 1 {
		t.Fatalf("task with regressed clock = (%v, calls=%d)", err, taskCalls)
	}

	evidence := validAlertEvidenceFixture(t, tenantID, alertID, 55)
	evidenceCalls := 0
	repository.resolveAlertAccess = allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityEvidenceManage)
	repository.mutateEvidence = func(_ context.Context, write AlertEvidenceMutationWrite) (MutationResult[kernel.AlertEvidence], error) {
		evidenceCalls++
		_, err := write.Apply(evidence)
		return MutationResult[kernel.AlertEvidence]{}, err
	}
	if _, err := service.AppendCustody(context.Background(), actor, tenantID, AlertCustodyCommand{
		AlertID: alertID, EvidenceID: evidence.ID(), ExpectedVersion: 1,
		EventID: testEntityID(t, 59), Action: kernel.CustodyAccessed, Reason: "review",
		Envelope: testEnvelope(60),
	}); !errors.Is(err, ErrUnavailable) || evidenceCalls != 1 {
		t.Fatalf("custody with regressed clock = (%v, calls=%d)", err, evidenceCalls)
	}

	tenant := testEntityIDFromUUID(t, tenantID)
	alert, _ := kernel.NewEntityReference(tenant, kernel.EntityAlert, alertID)
	asset, _ := kernel.NewEntityReference(tenant, kernel.EntityAsset, testEntityID(t, 61))
	relationship, err := kernel.NewAlertRelationship(kernel.AlertRelationshipState{
		ID: testEntityID(t, 62), TenantID: tenant, AlertID: alertID, Source: alert, Target: asset,
		RelationshipType: "contains", CreatedBy: testEntityID(t, 63), CreatedAt: testTime(10), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	relationshipCalls := 0
	repository.resolveAlertAccess = allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityRelationshipManage)
	repository.mutateRelationship = func(_ context.Context, write AlertRelationshipMutationWrite) (MutationResult[kernel.AlertRelationship], error) {
		relationshipCalls++
		_, err := write.Apply(relationship)
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	if _, err := service.RetractRelationship(context.Background(), actor, tenantID, AlertRelationshipRetractCommand{
		AlertID: alertID, RelationshipID: relationship.ID(), ExpectedVersion: 1,
		RetractionID: testEntityID(t, 64), Reason: "superseded", Envelope: testEnvelope(65),
	}); !errors.Is(err, ErrUnavailable) || relationshipCalls != 1 {
		t.Fatalf("relationship with regressed clock = (%v, calls=%d)", err, relationshipCalls)
	}
}

func TestAlertTaskExactReplayWinsBeforeCASUnderConcurrency(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(50), testEntityID(t, 51)
	actor := testActor(tenantID, PrincipalHuman)
	initial := validAlertTaskFixture(t, tenantID, alertID, 52)
	repository := newConcurrentAlertTaskRepository(actor, tenantID, alertID, initial)
	service := mustAlertInvestigationService(t, repository, testTime(60))
	command := AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: "start investigation", Envelope: testEnvelope(53),
	}
	const callers = 48
	var wait sync.WaitGroup
	var failures atomic.Int64
	var fresh atomic.Int64
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := service.TransitionTask(context.Background(), actor, tenantID, command)
			if err != nil || result.Resource.Version() != 2 || result.Resource.Status() != kernel.TaskInProgress {
				failures.Add(1)
				return
			}
			if !result.Replayed {
				fresh.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 || fresh.Load() != 1 || repository.effectCount() != 1 {
		t.Fatalf("concurrent replay = failures %d, fresh %d, effects %d", failures.Load(), fresh.Load(), repository.effectCount())
	}

	reused := command
	reused.Target = kernel.TaskCancelled
	if _, err := service.TransitionTask(context.Background(), actor, tenantID, reused); !errors.Is(err, ErrConflict) {
		t.Fatalf("same key/different request error = %v", err)
	}
	stale := command
	stale.Envelope = testEnvelope(54)
	if _, err := service.TransitionTask(context.Background(), actor, tenantID, stale); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("different key/stale CAS error = %v", err)
	}
}

func TestAlertTaskReplayDoesNotCanonicalizeInvalidTimeIntoValidRequest(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(60), testEntityID(t, 61)
	actor := testActor(tenantID, PrincipalHuman)
	initial := validAlertTaskFixture(t, tenantID, alertID, 62)
	repository := newConcurrentAlertTaskRepository(actor, tenantID, alertID, initial)
	service := mustAlertInvestigationService(t, repository, testTime(60))
	due := testTime(70)
	command := AlertTaskDueDateCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		DueAt: &due, Envelope: testEnvelope(63),
	}
	if result, err := service.RescheduleTask(context.Background(), actor, tenantID, command); err != nil || result.Replayed {
		t.Fatalf("valid reschedule = (replay=%t, %v)", result.Replayed, err)
	}
	offsetDue := due.In(time.FixedZone("UTC+01", 60*60))
	command.DueAt = &offsetDue
	if _, err := service.RescheduleTask(context.Background(), actor, tenantID, command); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("same key with non-UTC time error = %v, want invalid input", err)
	}
}

func TestAlertTaskRejectsRepositoryCallbackContractViolations(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(64), testEntityID(t, 65)
	actor := testActor(tenantID, PrincipalHuman)
	initial := validAlertTaskFixture(t, tenantID, alertID, 66)
	command := AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: initial.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: "start", Envelope: testEnvelope(67),
	}
	for name, mutate := range map[string]func(AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error){
		"fresh result altered after callback": func(write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
			updated, err := write.Apply(initial)
			if err != nil {
				return MutationResult[kernel.AlertTask]{}, err
			}
			state := updated.Snapshot()
			state.Description = "adapter substituted content"
			altered, err := kernel.NewAlertTask(state)
			return MutationResult[kernel.AlertTask]{Resource: altered}, err
		},
		"replay executes callback": func(write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
			updated, err := write.Apply(initial)
			return MutationResult[kernel.AlertTask]{Resource: updated, Replayed: true}, err
		},
		"fresh result skips callback": func(AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
			actorID, err := alertActorUserEntity(actor)
			if err != nil {
				return MutationResult[kernel.AlertTask]{}, err
			}
			updated, err := initial.Transition(kernel.TaskTransitionInput{
				ExpectedVersion: 1, Target: kernel.TaskInProgress, ActorID: actorID,
				OccurredAt: testTime(60), Reason: "start",
			})
			return MutationResult[kernel.AlertTask]{Resource: updated}, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &alertInvestigationRepositoryStub{
				resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
				mutateTask: func(_ context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
					return mutate(write)
				},
			}
			service := mustAlertInvestigationService(t, repository, testTime(60))
			if _, err := service.TransitionTask(context.Background(), actor, tenantID, command); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("callback contract error = %v", err)
			}
		})
	}
}

func TestAlertRelationshipNeverAcceptsRepositoryMergeAndRetractsAppendOnly(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(70), testEntityID(t, 71)
	actor := testActor(tenantID, PrincipalHuman)
	tenant := testEntityIDFromUUID(t, tenantID)
	alertReference, _ := kernel.NewEntityReference(tenant, kernel.EntityAlert, alertID)
	target, _ := kernel.NewEntityReference(tenant, kernel.EntityAsset, testEntityID(t, 72))
	command := AlertRelationshipCreateCommand{
		AlertID: alertID,
		Input: AlertRelationshipDraft{
			ID: testEntityID(t, 73), Source: alertReference, Target: target,
			RelationshipType: "contains", Metadata: []byte(`{"confidence":90}`),
		},
		Envelope: testEnvelope(74),
	}
	var stored kernel.AlertRelationship
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityRelationshipManage),
		commitRelationship: func(_ context.Context, write AlertRelationshipCreateWrite) (MutationResult[kernel.AlertRelationship], error) {
			assertAlertMutationContract(t, write.Contract, actor, alertID, CapabilityRelationshipManage, operationAlertRelationshipCreate)
			stored = write.Relationship
			return MutationResult[kernel.AlertRelationship]{Resource: stored}, nil
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(80))
	created, err := service.CreateRelationship(context.Background(), actor, tenantID, command)
	if err != nil || !created.Resource.Active() {
		t.Fatalf("CreateRelationship() = (%v, %v)", created.Resource, err)
	}

	repository.commitRelationship = func(_ context.Context, write AlertRelationshipCreateWrite) (MutationResult[kernel.AlertRelationship], error) {
		state := write.Relationship.Snapshot()
		state.ID = testEntityID(t, 75)
		merged, mergeErr := kernel.NewAlertRelationship(state)
		return MutationResult[kernel.AlertRelationship]{Resource: merged, Replayed: true}, mergeErr
	}
	if _, err := service.CreateRelationship(context.Background(), actor, tenantID, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("silent repository merge error = %v", err)
	}

	repository.mutateRelationship = func(_ context.Context, write AlertRelationshipMutationWrite) (MutationResult[kernel.AlertRelationship], error) {
		updated, applyErr := write.Apply(stored)
		if applyErr == nil {
			stored = updated
		}
		return MutationResult[kernel.AlertRelationship]{Resource: updated}, applyErr
	}
	retracted, err := service.RetractRelationship(context.Background(), actor, tenantID, AlertRelationshipRetractCommand{
		AlertID: alertID, RelationshipID: stored.ID(), ExpectedVersion: 1,
		RetractionID: testEntityID(t, 76), Reason: "invalidated", Envelope: testEnvelope(77),
	})
	if err != nil || retracted.Resource.Active() || len(retracted.Resource.Retractions()) != 1 {
		t.Fatalf("RetractRelationship() = (%v, %v)", retracted.Resource, err)
	}
	if _, err := service.RetractRelationship(context.Background(), actor, tenantID, AlertRelationshipRetractCommand{
		AlertID: alertID, RelationshipID: stored.ID(), ExpectedVersion: 2,
		RetractionID: testEntityID(t, 78), Reason: "second", Envelope: testEnvelope(79),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("second retraction error = %v", err)
	}
}

func TestAlertInvestigationCancellationAndCustomerMutationFailClosed(t *testing.T) {
	t.Parallel()
	tenantID, alertID := testUUID(90), testEntityID(t, 91)
	actor := testActor(tenantID, PrincipalHuman)
	resolves := 0
	repository := &alertInvestigationRepositoryStub{
		resolveAlertAccess: func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
			resolves++
			return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
		},
	}
	service := mustAlertInvestigationService(t, repository, testTime(100))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.CreateTask(canceled, actor, tenantID, AlertTaskCreateCommand{
		AlertID: alertID, Input: validAlertTaskDraft(t, 92), Envelope: testEnvelope(93),
	}); !errors.Is(err, context.Canceled) || resolves != 0 {
		t.Fatalf("canceled task create = (%v, resolves=%d)", err, resolves)
	}
	if _, err := service.CreateTask(context.Background(), testActor(tenantID, PrincipalCustomer), tenantID, AlertTaskCreateCommand{
		AlertID: alertID, Input: validAlertTaskDraft(t, 92), Envelope: testEnvelope(93),
	}); !errors.Is(err, ErrForbidden) || resolves != 0 {
		t.Fatalf("customer task create = (%v, resolves=%d)", err, resolves)
	}
	if _, err := service.Workspace(nil, actor, tenantID, alertID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error = %v", err)
	}

	current := validAlertTaskFixture(t, tenantID, alertID, 94)
	ctx, cancelDuringMutation := context.WithCancel(context.Background())
	effects := 0
	repository.resolveAlertAccess = allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage)
	repository.mutateTask = func(_ context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
		cancelDuringMutation()
		updated, applyErr := write.Apply(current)
		if applyErr == nil {
			effects++
		}
		return MutationResult[kernel.AlertTask]{Resource: updated}, applyErr
	}
	if _, err := service.TransitionTask(ctx, actor, tenantID, AlertTaskTransitionCommand{
		AlertID: alertID, TaskID: current.ID(), ExpectedVersion: 1,
		Target: kernel.TaskInProgress, Reason: "start", Envelope: testEnvelope(95),
	}); !errors.Is(err, context.Canceled) || effects != 0 {
		t.Fatalf("cancellation inside callback = (%v, effects=%d)", err, effects)
	}
}

type alertInvestigationRepositoryStub struct {
	resolveAlertAccess func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error)
	loadWorkspace      func(context.Context, Actor, uuid.UUID, kernel.EntityID, WorkspaceAccess) (AlertInvestigationWorkspace, error)
	commitEvidence     func(context.Context, AlertEvidenceCreateWrite) (MutationResult[kernel.AlertEvidence], error)
	mutateEvidence     func(context.Context, AlertEvidenceMutationWrite) (MutationResult[kernel.AlertEvidence], error)
	commitTask         func(context.Context, AlertTaskCreateWrite) (MutationResult[kernel.AlertTask], error)
	mutateTask         func(context.Context, AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error)
	commitRelationship func(context.Context, AlertRelationshipCreateWrite) (MutationResult[kernel.AlertRelationship], error)
	mutateRelationship func(context.Context, AlertRelationshipMutationWrite) (MutationResult[kernel.AlertRelationship], error)
}

func (repository *alertInvestigationRepositoryStub) ResolveAlertAccess(ctx context.Context, actor Actor, tenantID uuid.UUID, capability Capability, scope AlertResourceScope) (Access, error) {
	if repository.resolveAlertAccess == nil {
		return Access{}, ErrRepositoryForbidden
	}
	return repository.resolveAlertAccess(ctx, actor, tenantID, capability, scope)
}

func (repository *alertInvestigationRepositoryStub) LoadAlertInvestigationWorkspace(ctx context.Context, actor Actor, tenantID uuid.UUID, alertID kernel.EntityID, access WorkspaceAccess) (AlertInvestigationWorkspace, error) {
	if repository.loadWorkspace == nil {
		return AlertInvestigationWorkspace{}, ErrRepositoryNotFound
	}
	return repository.loadWorkspace(ctx, actor, tenantID, alertID, access)
}

func (repository *alertInvestigationRepositoryStub) CommitAlertEvidence(ctx context.Context, write AlertEvidenceCreateWrite) (MutationResult[kernel.AlertEvidence], error) {
	if repository.commitEvidence == nil {
		return MutationResult[kernel.AlertEvidence]{}, ErrRepositoryNotFound
	}
	return repository.commitEvidence(ctx, write)
}

func (repository *alertInvestigationRepositoryStub) MutateAlertEvidence(ctx context.Context, write AlertEvidenceMutationWrite) (MutationResult[kernel.AlertEvidence], error) {
	if repository.mutateEvidence == nil {
		return MutationResult[kernel.AlertEvidence]{}, ErrRepositoryNotFound
	}
	return repository.mutateEvidence(ctx, write)
}

func (repository *alertInvestigationRepositoryStub) CommitAlertTask(ctx context.Context, write AlertTaskCreateWrite) (MutationResult[kernel.AlertTask], error) {
	if repository.commitTask == nil {
		return MutationResult[kernel.AlertTask]{}, ErrRepositoryNotFound
	}
	return repository.commitTask(ctx, write)
}

func (repository *alertInvestigationRepositoryStub) MutateAlertTask(ctx context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
	if repository.mutateTask == nil {
		return MutationResult[kernel.AlertTask]{}, ErrRepositoryNotFound
	}
	return repository.mutateTask(ctx, write)
}

func (repository *alertInvestigationRepositoryStub) CommitAlertRelationship(ctx context.Context, write AlertRelationshipCreateWrite) (MutationResult[kernel.AlertRelationship], error) {
	if repository.commitRelationship == nil {
		return MutationResult[kernel.AlertRelationship]{}, ErrRepositoryNotFound
	}
	return repository.commitRelationship(ctx, write)
}

func (repository *alertInvestigationRepositoryStub) MutateAlertRelationship(ctx context.Context, write AlertRelationshipMutationWrite) (MutationResult[kernel.AlertRelationship], error) {
	if repository.mutateRelationship == nil {
		return MutationResult[kernel.AlertRelationship]{}, ErrRepositoryNotFound
	}
	return repository.mutateRelationship(ctx, write)
}

type concurrentAlertTaskRepository struct {
	*alertInvestigationRepositoryStub
	mutex    sync.Mutex
	task     kernel.AlertTask
	receipts map[[32]byte]taskMutationReceipt
	effects  int
}

type taskMutationReceipt struct {
	request [32]byte
	task    kernel.AlertTask
}

func newConcurrentAlertTaskRepository(actor Actor, tenantID uuid.UUID, alertID kernel.EntityID, task kernel.AlertTask) *concurrentAlertTaskRepository {
	repository := &concurrentAlertTaskRepository{
		task: task, receipts: make(map[[32]byte]taskMutationReceipt),
	}
	repository.alertInvestigationRepositoryStub = &alertInvestigationRepositoryStub{
		resolveAlertAccess: allowAlertInvestigationAccess(actor, tenantID, alertID, CapabilityTaskManage),
	}
	return repository
}

func (repository *concurrentAlertTaskRepository) MutateAlertTask(_ context.Context, write AlertTaskMutationWrite) (MutationResult[kernel.AlertTask], error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	key := write.Contract.Command.KeyDigest
	if receipt, exists := repository.receipts[key]; exists {
		if receipt.request != write.Contract.Command.RequestDigest {
			return MutationResult[kernel.AlertTask]{}, ErrRepositoryConflict
		}
		return MutationResult[kernel.AlertTask]{Resource: receipt.task, Replayed: true}, nil
	}
	updated, err := write.Apply(repository.task)
	if err != nil {
		return MutationResult[kernel.AlertTask]{}, err
	}
	repository.task = updated
	repository.receipts[key] = taskMutationReceipt{request: write.Contract.Command.RequestDigest, task: updated}
	repository.effects++
	return MutationResult[kernel.AlertTask]{Resource: updated}, nil
}

func (repository *concurrentAlertTaskRepository) effectCount() int {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	return repository.effects
}

func mustAlertInvestigationService(t *testing.T, repository AlertInvestigationRepository, now time.Time) *AlertInvestigationService {
	t.Helper()
	service, err := NewAlertInvestigationService(repository, AlertInvestigationServiceConfig{
		Bucket: "periapsis-evidence", Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func allowAlertInvestigationAccess(actor Actor, tenantID uuid.UUID, alertID kernel.EntityID, capability Capability) func(context.Context, Actor, uuid.UUID, Capability, AlertResourceScope) (Access, error) {
	return func(_ context.Context, got Actor, gotTenant uuid.UUID, gotCapability Capability, scope AlertResourceScope) (Access, error) {
		if got != actor || gotTenant != tenantID || gotCapability != capability || scope.AlertID != alertID {
			return Access{}, ErrRepositoryForbidden
		}
		return Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}, nil
	}
}

func assertAlertMutationContract(t *testing.T, contract AlertMutationContract, actor Actor, alertID kernel.EntityID, capability Capability, operation string) {
	t.Helper()
	effects, ok := alertEffects(operation)
	if !ok {
		t.Fatalf("unknown Alert operation %q", operation)
	}
	if contract.Actor != actor || contract.AlertID != alertID || contract.CaseID != (kernel.EntityID{}) ||
		contract.Capability != capability || contract.Access != (Access{Audience: kernel.AudienceOperator, Scope: ScopeTenant}) ||
		contract.Command.Operation != operation || contract.Command.KeyDigest == ([32]byte{}) ||
		contract.Command.RequestDigest == ([32]byte{}) || contract.Audit.RequestID == uuid.Nil ||
		contract.Audit.CorrelationID == uuid.Nil || !contract.Audit.IPAddress.IsValid() ||
		contract.ActivityType != effects.activity || contract.AuditAction != effects.audit ||
		!validAlertSingleLineText(contract.AuditReason, 2_000, false) ||
		contract.OutboxEventType != effects.outbox {
		t.Fatalf("incomplete Alert transaction contract: %#v", contract)
	}
}

func validAlertInvestigationWorkspaceFixture(t *testing.T, tenantID uuid.UUID, alertID kernel.EntityID) AlertInvestigationWorkspace {
	t.Helper()
	tenant := testEntityIDFromUUID(t, tenantID)
	alertReference, _ := kernel.NewEntityReference(tenant, kernel.EntityAlert, alertID)
	asset, _ := kernel.NewEntityReference(tenant, kernel.EntityAsset, testEntityID(t, 8))
	relationship, err := kernel.NewAlertRelationship(kernel.AlertRelationshipState{
		ID: testEntityID(t, 9), TenantID: tenant, AlertID: alertID,
		Source: alertReference, Target: asset, RelationshipType: "contains",
		CreatedBy: testEntityID(t, 7), CreatedAt: testTime(10), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return AlertInvestigationWorkspace{
		Evidence:      []kernel.AlertEvidence{validAlertEvidenceFixture(t, tenantID, alertID, 5)},
		Tasks:         []kernel.AlertTask{validAlertTaskFixture(t, tenantID, alertID, 6)},
		Relationships: []kernel.AlertRelationship{relationship},
	}
}

func validAlertEvidenceFixture(t *testing.T, tenantID uuid.UUID, alertID kernel.EntityID, seed byte) kernel.AlertEvidence {
	t.Helper()
	storage := availableStorageObject(t, tenantID, seed, testTime(0))
	evidence, err := kernel.NewAlertEvidence(kernel.AlertEvidenceInput{
		ID: testEntityID(t, seed+20), TenantID: testEntityIDFromUUID(t, tenantID), AlertID: alertID,
		StorageObjectID: storage.ID(), InitialCustodyEventID: testEntityID(t, seed+21),
		Title: "Memory image", Description: "Private forensic metadata", EvidenceType: "memory_image",
		Classification: storage.Classification(), ContentSHA256: storage.ContentSHA256(),
		SizeBytes: storage.SizeBytes(), DetectedMIME: storage.DetectedMIME(),
		CollectedAt: testTime(10), CollectedBy: testEntityID(t, seed+22),
		InitialCustodyActorID: testEntityID(t, seed+23), Source: "endpoint_sensor",
		ScanState: storage.State(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func validAlertTaskFixture(t *testing.T, tenantID uuid.UUID, alertID kernel.EntityID, seed byte) kernel.AlertTask {
	t.Helper()
	task, err := kernel.NewAlertTask(kernel.AlertTaskState{
		ID: testEntityID(t, seed), TenantID: testEntityIDFromUUID(t, tenantID), AlertID: alertID,
		Title: "Collect volatile memory", Description: "Private task details",
		Status: kernel.TaskTodo, Priority: kernel.TaskPriorityHigh,
		CreatedAt: testTime(10), UpdatedAt: testTime(10), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func validAlertTaskDraft(t *testing.T, seed byte) AlertTaskDraft {
	t.Helper()
	return AlertTaskDraft{
		ID: testEntityID(t, seed), Title: "Collect volatile memory",
		Description: "Private task details", Priority: kernel.TaskPriorityHigh,
	}
}

func validAlertEvidenceCollectCommand(t *testing.T, alertID, storageID kernel.EntityID, seed byte) AlertEvidenceCollectCommand {
	t.Helper()
	return AlertEvidenceCollectCommand{
		AlertID: alertID, EvidenceID: testEntityID(t, seed), StorageObjectID: storageID,
		InitialCustodyEventID: testEntityID(t, seed+1), Title: "Memory image",
		Description: "Private forensic metadata", EvidenceType: "memory_image",
		Classification: kernel.EvidenceInternal, CollectedAt: testTime(10), Source: "endpoint_sensor",
		Envelope: testEnvelope(seed + 2),
	}
}
