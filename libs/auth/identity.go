package auth

import (
	"fmt"
	"strings"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

type IdentityOption func(*IdentityOptions)

type IdentityOptions struct {
	DeviceId string            `json:"device_id"`
	Display  string            `json:"display,omitempty"`
	Private  bool              `json:"private,omitempty"`
	Proof    *EncodableAttempt `json:"proof,omitempty"`
}

func (i IdentityOptions) Update(fns ...IdentityOption) (ret IdentityOptions) {
	ret = i
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func BuildIdentityOptions(fns ...IdentityOption) (ret IdentityOptions) {
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func WithPrivacy() IdentityOption {
	return func(o *IdentityOptions) {
		o.Private = true
	}
}

func WithDeviceID(id string) IdentityOption {
	return func(o *IdentityOptions) {
		o.DeviceId = id
	}
}

func WithDisplay(str string, args ...interface{}) IdentityOption {
	return func(o *IdentityOptions) {
		o.Display = fmt.Sprintf(str, args...)
	}
}

func WithProof(attmpt Attempt) IdentityOption {
	return func(o *IdentityOptions) {
		o.Proof = &EncodableAttempt{attmpt}
	}
}

// *** IDENTITY PROTOCOLS *** //

// The protocol to be used.
type Protocol string

const (
	Email Protocol = "email"
	Phone          = "phone"
	Key            = "key"
	UUID           = "uuid"
	User           = "user"
	Pem            = "pem"
)

func (p Protocol) String() string {
	return string(p)
}

func (p Protocol) Apply(base string) string {
	return fmt.Sprintf("%v://%v", p, base)
}

// *** IDENTITY IMPLEMENTATION *** //

var EmptyId = Identity{}

// Returns true if a list of identities contains
// a given id, false otherwise.
func ContainsIdentity(all []Identity, id Identity) bool {
	for _, cur := range all {
		if cur == id {
			return true
		}
	}
	return false
}

// An identity is a verifiable public address of an account.  All identities
// must be globally unique if they are to be stored.
type Identity struct {
	Proto Protocol
	Val   string
}

func (i Identity) Uri() string {
	return fmt.Sprintf("%v://%v", i.Proto, i.Val)
}

func (i Identity) String() string {
	return i.Uri()
}

func (i Identity) Protocol() Protocol {
	return i.Proto
}

func (i Identity) Value() string {
	return i.Val
}

func (i Identity) MarshalText() ([]byte, error) {
	return []byte(i.Uri()), nil
}

func (i *Identity) UnmarshalText(text []byte) (err error) {
	tmp, err := ByStdUri(string(text))
	if err != nil {
		return
	}
	*i = tmp
	return
}

func Weight(id Identity) int {
	switch id.Protocol() {
	default:
		return 0
	case User:
		return 40
	case Email:
		return 30
	case Phone:
		return 20
	case UUID:
		return 10
	case Key:
		return 1
	}
}

// *** SUPPORTED IDENTITIES *** //

var (
	ParseIdentity = ByStdUri
)

func ByStdUri(uri string) (ret Identity, err error) {
	parts := strings.SplitN(uri, "://", 2)
	if len(parts) != 2 {
		err = errors.Wrapf(errs.ArgError, "Illegal format [%v]", uri)
		return
	}

	ret = Identity{Protocol(parts[0]), parts[1]}
	return
}

func ByUri(uri string) Identity {
	parts := strings.SplitN(uri, "://", 2)
	if len(parts) != 2 {
		panic(fmt.Sprintf("Bad uri [%v]", uri))
	}
	return Identity{Protocol(parts[0]), parts[1]}
}

func ByEmail(email string) Identity {
	return Identity{Email, email}
}

func ByPhone(phone string) Identity {
	return Identity{Phone, phone}
}

func ById(id uuid.UUID) Identity {
	return Identity{UUID, id.String()}
}

func ByUser(alias string) Identity {
	return Identity{User, alias}
}

func ByKey(key crypto.PublicKey) Identity {
	return ByKeyId(key.ID())
}

func ByKeyId(id string) Identity {
	return Identity{Key, id}
}

func ByPemFile(file string) Identity {
	return Identity{Pem, file}
}
