package httpserver

import (
	"context"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

// transportLDAPAdministrationStub keeps unrelated transport tests fail closed.
// LDAP administration tests use a configurable fake in their own test file.
type transportLDAPAdministrationStub struct {
	searchUser      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UserSearchTestInput) (identityprovider.DirectoryTestResult, error)
	testFilter      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FilterTestInput) (identityprovider.DirectoryTestResult, error)
	listBindings    func(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListBindingsInput) (identityprovider.BindingPage, error)
	createBinding   func(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateBindingInput) (identityprovider.Binding, error)
	getBinding      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Binding, error)
	updateBinding   func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UpdateBindingInput) (identityprovider.Binding, error)
	archiveBinding  func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ArchiveBindingInput) (int64, error)
	listMappings    func(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListMappingsInput) (identityprovider.MappingPage, error)
	createMapping   func(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateMappingInput) (identityprovider.Mapping, error)
	dryRunMappings  func(context.Context, authorization.Actor, uuid.UUID, identityprovider.DryRunInput) (identityprovider.DryRunResult, error)
	getMapping      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Mapping, error)
	updateMapping   func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UpdateMappingInput) (identityprovider.Mapping, error)
	archiveMapping  func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ArchiveMappingInput) (int64, error)
	getSyncStatus   func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.SyncStatus, error)
	listSyncRuns    func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.PageInput) (identityprovider.SyncRunPage, error)
	startManualSync func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.StartManualSyncInput) (identityprovider.SyncRun, error)
	getSyncRun      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (identityprovider.SyncRun, error)
}

func (s *transportLDAPAdministrationStub) SearchUser(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.UserSearchTestInput) (identityprovider.DirectoryTestResult, error) {
	if s.searchUser != nil {
		return s.searchUser(ctx, actor, tenantID, providerID, input)
	}
	return identityprovider.DirectoryTestResult{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) TestFilter(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FilterTestInput) (identityprovider.DirectoryTestResult, error) {
	if s.testFilter != nil {
		return s.testFilter(ctx, actor, tenantID, providerID, input)
	}
	return identityprovider.DirectoryTestResult{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) ListBindings(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.ListBindingsInput) (identityprovider.BindingPage, error) {
	if s.listBindings != nil {
		return s.listBindings(ctx, actor, tenantID, input)
	}
	return identityprovider.BindingPage{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) CreateBinding(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.CreateBindingInput) (identityprovider.Binding, error) {
	if s.createBinding != nil {
		return s.createBinding(ctx, actor, tenantID, input)
	}
	return identityprovider.Binding{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) GetBinding(ctx context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID) (identityprovider.Binding, error) {
	if s.getBinding != nil {
		return s.getBinding(ctx, actor, tenantID, bindingID)
	}
	return identityprovider.Binding{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) UpdateBinding(ctx context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.UpdateBindingInput) (identityprovider.Binding, error) {
	if s.updateBinding != nil {
		return s.updateBinding(ctx, actor, tenantID, bindingID, input)
	}
	return identityprovider.Binding{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) ArchiveBinding(ctx context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.ArchiveBindingInput) (int64, error) {
	if s.archiveBinding != nil {
		return s.archiveBinding(ctx, actor, tenantID, bindingID, input)
	}
	return 0, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) ListMappings(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.ListMappingsInput) (identityprovider.MappingPage, error) {
	if s.listMappings != nil {
		return s.listMappings(ctx, actor, tenantID, input)
	}
	return identityprovider.MappingPage{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) CreateMapping(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.CreateMappingInput) (identityprovider.Mapping, error) {
	if s.createMapping != nil {
		return s.createMapping(ctx, actor, tenantID, input)
	}
	return identityprovider.Mapping{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) DryRunMappings(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.DryRunInput) (identityprovider.DryRunResult, error) {
	if s.dryRunMappings != nil {
		return s.dryRunMappings(ctx, actor, tenantID, input)
	}
	return identityprovider.DryRunResult{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) GetMapping(ctx context.Context, actor authorization.Actor, tenantID, mappingID uuid.UUID) (identityprovider.Mapping, error) {
	if s.getMapping != nil {
		return s.getMapping(ctx, actor, tenantID, mappingID)
	}
	return identityprovider.Mapping{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) UpdateMapping(ctx context.Context, actor authorization.Actor, tenantID, mappingID uuid.UUID, input identityprovider.UpdateMappingInput) (identityprovider.Mapping, error) {
	if s.updateMapping != nil {
		return s.updateMapping(ctx, actor, tenantID, mappingID, input)
	}
	return identityprovider.Mapping{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) ArchiveMapping(ctx context.Context, actor authorization.Actor, tenantID, mappingID uuid.UUID, input identityprovider.ArchiveMappingInput) (int64, error) {
	if s.archiveMapping != nil {
		return s.archiveMapping(ctx, actor, tenantID, mappingID, input)
	}
	return 0, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) GetSyncStatus(ctx context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID) (identityprovider.SyncStatus, error) {
	if s.getSyncStatus != nil {
		return s.getSyncStatus(ctx, actor, tenantID, bindingID)
	}
	return identityprovider.SyncStatus{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) ListSyncRuns(ctx context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.PageInput) (identityprovider.SyncRunPage, error) {
	if s.listSyncRuns != nil {
		return s.listSyncRuns(ctx, actor, tenantID, bindingID, input)
	}
	return identityprovider.SyncRunPage{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) StartManualSync(ctx context.Context, actor authorization.Actor, tenantID, bindingID uuid.UUID, input identityprovider.StartManualSyncInput) (identityprovider.SyncRun, error) {
	if s.startManualSync != nil {
		return s.startManualSync(ctx, actor, tenantID, bindingID, input)
	}
	return identityprovider.SyncRun{}, identityprovider.ErrUnavailable
}

func (s *transportLDAPAdministrationStub) GetSyncRun(ctx context.Context, actor authorization.Actor, tenantID, bindingID, syncRunID uuid.UUID) (identityprovider.SyncRun, error) {
	if s.getSyncRun != nil {
		return s.getSyncRun(ctx, actor, tenantID, bindingID, syncRunID)
	}
	return identityprovider.SyncRun{}, identityprovider.ErrUnavailable
}
