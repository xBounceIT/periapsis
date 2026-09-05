package tenantsettings

import "context"

type Repository interface {
	Get(context.Context, ReadParams) (Settings, error)
	Update(context.Context, UpdateParams) (Settings, error)
}
