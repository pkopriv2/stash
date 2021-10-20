package auth

import (
	"time"

	"github.com/cott-io/stash/lang/crypto"
	uuid "github.com/satori/go.uuid"
)

type AuthOption func(*AuthOptions)

// Various authentication options.  This introduces
// a logical cycle in the packages wrt to orgs, however,
// in reality this means we just have "named" fields as strings
// and ids representing their correspoding package components.
type AuthOptions struct {
	Expires  time.Duration `json:"ttl"`
	OrgId    uuid.UUID     `json:"org_id,omitempty"`
	DeviceId string        `json:"device_id,omitempty"`
}

func (a AuthOptions) Update(opts ...AuthOption) (ret AuthOptions) {
	ret = a
	for _, fn := range opts {
		fn(&ret)
	}
	return
}

func BuildOptions(fns ...AuthOption) (ret AuthOptions) {
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func WithTimeout(ttl time.Duration) AuthOption {
	return func(o *AuthOptions) {
		o.Expires = ttl
	}
}

func WithDeviceId(id string) AuthOption {
	return func(o *AuthOptions) {
		o.DeviceId = id
	}
}

func WithOrgId(id uuid.UUID) AuthOption {
	return func(o *AuthOptions) {
		o.OrgId = id
	}
}

type ServerInfo struct {
	Version string
	Key     crypto.PublicKey
	Expires time.Duration
	Now     time.Time
}

// Core transport mechanism.
type Transport interface {

	// Auths with the account service.  If an org is provided the returned token will have a corresponding org claim on the token
	Authenticate(id Identity, attempt Attempt, opts AuthOptions) (SignedToken, error)
}
