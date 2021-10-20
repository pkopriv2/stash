package policies

import (
	"strings"
	"sync"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	UserType = user{}
)

func init() {
	StaticMemberTypes.Register(UserType)
}

type MemberType interface {
	Type() policy.Type
	GetMemberId(s session.Session, orgId uuid.UUID, name string) (uuid.UUID, error)
	GetPublicKey(s session.Session, orgId, memberId uuid.UUID) (crypto.PublicKey, error)
}

var (
	StaticMemberTypes = MemberTypeRegistry{
		&sync.RWMutex{},
		make(map[string]MemberType)}
)

type MemberTypeRegistry struct {
	lock    *sync.RWMutex
	byProto map[string]MemberType
}

func (t MemberTypeRegistry) Register(info MemberType) {
	t.lock.Lock()
	defer t.lock.Unlock()
	name := strings.ToLower(string(info.Type()))
	if name == "" {
		panic("Invalid type. Must have a non-zero name")
	}

	t.byProto[name] = info
}

func (t MemberTypeRegistry) LookupByProtocol(proto string) (ret MemberType, ok bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	ret, ok = t.byProto[proto]
	return
}

//  A member ref is a parsed identifier of a member.
//  Members, by definition, are the entities that
//  are allowed to be associated to policies.
type MemberRef struct {
	Type MemberType
	id   *uuid.UUID
	name *string
}

func newMemberRef(t MemberType, raw string) MemberRef {
	if id, err := uuid.FromString(raw); err == nil {
		return MemberRef{Type: t, id: &id}
	} else {
		return MemberRef{Type: t, name: &raw}
	}
}

func (r MemberRef) ToItem() (ItemRef, error) {
	return ParseItemRef(r.String())
}

func (r MemberRef) GetMemberId(s session.Session, orgId uuid.UUID) (uuid.UUID, error) {
	if r.id != nil {
		return *r.id, nil
	} else {
		return r.Type.GetMemberId(s, orgId, *r.name)
	}
}

func (m MemberRef) Name() string {
	if m.id != nil {
		return m.id.String()
	} else {
		return *m.name
	}
}

func (m MemberRef) String() string {
	t := m.Type.Type()
	if m.id != nil {
		return t.FormatId(*m.id)
	} else {
		return t.FormatName(*m.name)
	}
}

func ParseMemberRef(uri string) (ret MemberRef, err error) {
	ptr := ref.Pointer(uri)

	typ, ok := StaticMemberTypes.LookupByProtocol(ptr.Protocol())
	if !ok {
		err = errors.Wrapf(errs.ArgError, "Unknown type for [%v]", uri)
		return
	}

	ret = newMemberRef(typ, ptr.Document())
	return
}

type user struct {
}

func (u user) Type() policy.Type {
	return policy.UserType
}

func (u user) GetMemberId(s session.Session, orgId uuid.UUID, name string) (memberId uuid.UUID, err error) {
	id, err := auth.LoadIdentity(name)
	if err != nil {
		return
	}

	info, err := accounts.RequireIdentity(s, id)
	if err != nil {
		return
	}

	memberId = info.AccountId
	return
}

func (u user) GetPublicKey(s session.Session, orgId, memberId uuid.UUID) (pub crypto.PublicKey, err error) {
	pub, err = accounts.RequirePublicKey(s, memberId)
	return
}
