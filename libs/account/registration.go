package account

import (
	"github.com/cott-io/stash/libs/auth"
)

type RegistrationOption func(*RegistrationOptions)

// RegistrationOptions are the request level data for setting up
// an account.  The options are exected to be consistent with the
// the associated account.
type RegistrationOptions struct {
	auth.IdentityOptions `json:"primary_opts"`
}

func BuildRegistrationOptions(opts ...RegistrationOption) (ret RegistrationOptions) {
	ret = RegistrationOptions{}
	for _, fn := range opts {
		fn(&ret)
	}
	return
}

func WithIdentityOptions(opts ...auth.IdentityOption) RegistrationOption {
	return func(s *RegistrationOptions) {
		s.IdentityOptions = auth.BuildIdentityOptions(opts...)
	}
}
