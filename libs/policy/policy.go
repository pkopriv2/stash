package policy

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/libs/auth"
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/emirpasic/gods/utils"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// This package implements a generic, zero-trust access
// policy system.
var (
	ErrNoGroup     = errors.New("Policy:NoGroup")
	ErrNoPolicy    = errors.New("Policy:NoPolicy")
	ErrNotAMember  = errors.New("Policy:NotAMember")
	ErrSyntax      = errors.New("Policy:ErrSyntax")
	ErrEmptyPolicy = errors.New("Policy:Empty")
)

const (
	NoneType  = "none"
	UserType  = "user"
	GroupType = "group"
	ProxyType = "proxy"
)

type Type string

func (m Type) FormatName(name string) string {
	return fmt.Sprintf("%v://%v", m, name)
}

func (m Type) FormatId(id uuid.UUID) string {
	return fmt.Sprintf("%v://%v", m, id)
}

type PolicyMemberInfo struct {
	PolicyMember `json:"member"`
	User         *auth.Identity `json:"user,omitempty"`  // only set if user type
	Group        *string        `json:"group,omitempty"` // only set if group type
}

func (p PolicyMemberInfo) Format() string {
	switch p.MemberType {
	case UserType:
		if p.User != nil {
			return p.MemberType.FormatName(auth.FormatFriendlyIdentity(*p.User))
		}
	case GroupType:
		if p.Group != nil {
			return p.MemberType.FormatName(*p.Group)
		}
	}

	return p.MemberType.FormatId(p.MemberId)
}

type Sorter func(a, b interface{}) int

func FormatSorter(a, b interface{}) int {
	return strings.Compare(a.(PolicyMemberInfo).Format(), b.(PolicyMemberInfo).Format())
}

// Sorts the policy members using the given sorter
func SortPolicyMembers(members []PolicyMemberInfo, sort Sorter) (ret []PolicyMemberInfo) {
	data := treeset.NewWith(utils.Comparator(sort))
	for _, m := range members {
		data.Add(m)
	}

	ret = make([]PolicyMemberInfo, 0, data.Size())
	for _, m := range data.Values() {
		ret = append(ret, m.(PolicyMemberInfo))
	}
	return
}

// A policy lock contains all of the pieces necessary
// to access a policy for a given user.  This will be the
// primary interface to a policy for callers simply wishing
// to access the policy secret.
type PolicyLock struct {
	Core       Policy       `json:"core"`
	CoreMember PolicyMember `json:"core_member"`

	// Optional fields.  Set depending on the access path!
	Group       Policy       `json:"proxy1,omitempty"`
	GroupMember PolicyMember `json:"proxy1_member,omitempty"`
}

// Returns the org id of the policy
func (u PolicyLock) OrgId() (ret uuid.UUID) {
	ret = u.Core.OrgId
	return
}

// Returns the id of the policy
func (u PolicyLock) Id() (ret uuid.UUID) {
	ret = u.Core.Id
	return
}

// Returns the public key of the policy
func (u PolicyLock) PublicKey() (ret crypto.PublicKey) {
	ret = u.Core.Key.Pub
	return
}

// Returns the policy's strength option.
func (u PolicyLock) Actions() (ret Actions) {
	ret = Unflatten(append(u.CoreMember.Actions.Flatten(), u.GroupMember.Actions.Flatten()...))
	return
}

// Returns the policy's strength option.
func (u PolicyLock) Strength() (ret crypto.Strength) {
	ret = u.Core.Strength
	return
}

// Decrypts the secret using the caller's private key.
func (p PolicyLock) RecoverSecret(rand io.Reader, callerKey crypto.PrivateKey) (ret crypto.Bytes, err error) {
	temp := callerKey
	if p.Group.Key.Pub != nil {
		temp, err = p.Group.RecoverPrivateKey(rand, p.GroupMember, temp)
		if err != nil {
			return
		}
	}

	ret, err = p.Core.RecoverSecret(rand, p.CoreMember, temp)
	return
}

// Decrypts the secret using the caller's private key.
func (p PolicyLock) RecoverPrivateKey(rand io.Reader, callerKey crypto.PrivateKey) (ret crypto.PrivateKey, err error) {
	temp := callerKey
	if p.Group.Key.Pub != nil {
		temp, err = p.Group.RecoverPrivateKey(rand, p.GroupMember, temp)
		if err != nil {
			return
		}
	}

	ret, err = p.Core.RecoverPrivateKey(rand, p.CoreMember, temp)
	return
}

// Adds a member directly to the policy
func (p PolicyLock) AddMember(rand io.Reader, callerKey crypto.PrivateKey, memberId uuid.UUID, memberType Type, memberKey crypto.PublicKey, actions ...Action) (ret PolicyMember, err error) {
	temp := callerKey
	if p.Group.Key.Pub != nil {
		temp, err = p.Group.RecoverPrivateKey(rand, p.GroupMember, temp)
		if err != nil {
			return
		}
	}
	ret, err = p.Core.AddMember(rand, p.CoreMember, temp, memberId, memberType, memberKey, actions...)
	return
}

// A policy is a structure that protects and manages access to
// a shared secret, whose value is used to protect an external
// asset.
//
// Policies are composed of the primary secret - encrypted using
// a shared password - and a collection of memberships that grant
// access to members.  Each membership may have a custom list of
// enabled actions.
//
// The specific values of actions are specific to the asset that is
// under management of the policy.
//
type Policy struct {
	OrgId    uuid.UUID               `json:"org_id"`
	Id       uuid.UUID               `json:"id"`
	Version  int                     `json:"version"`
	Created  time.Time               `json:"created"`
	Updated  time.Time               `json:"updated"`
	Deleted  bool                    `json:"deleted"`
	Key      crypto.KeyPair          `json:"key"`
	Secret   crypto.SaltedCipherText `json:"secret"`
	Strength crypto.Strength         `json:"strength"`
}

func GenPolicyUnsafe(rand io.Reader,
	orgId, ownerId uuid.UUID, ownerKey crypto.PublicKey, ownerType Type, strength crypto.Strength, actions ...Action) (policy PolicyLock, secret []byte, err error) {

	// the pass is the secret that's actually shared amongst the members
	// that allows them to decrypt the actual secret.  For the purposes
	// of further encryption, the secret should be preferred.
	pass, err := strength.GenNonce(rand)
	if err != nil {
		return
	}
	defer crypto.Bytes(pass).Destroy()

	// This is the private key of the policy.  This gives an identity to the
	// policy and can be used to make 'this' policy the member of another.
	priv, err := strength.GenKey(rand, crypto.RSA)
	if err != nil {
		return
	}
	defer crypto.Destroy(priv)

	// Generate the encrypted key pair
	pair, err := strength.GenKeyPair(rand, enc.Json, priv, pass)
	if err != nil {
		return
	}

	// This is the secret of the policy.  This is the value that may be used
	// as a seed for further encryption.
	secret, err = strength.GenNonce(rand)
	if err != nil {
		return
	}

	accessor, err := GenMemberSecret(rand, ownerKey, pass, strength)
	if err != nil {
		return
	}

	ciphertext, err := strength.SaltAndEncrypt(rand, pass, secret)
	if err != nil {
		return
	}

	id, now := uuid.NewV4(), time.Now().UTC()
	policy = PolicyLock{
		Core: Policy{
			Id:       id,
			OrgId:    orgId,
			Created:  now,
			Updated:  now,
			Key:      pair,
			Secret:   ciphertext,
			Strength: strength,
		},
		CoreMember: PolicyMember{
			OrgId:      orgId,
			PolicyId:   id,
			MemberType: ownerType,
			MemberId:   ownerId,
			Created:    now,
			Updated:    now,
			Pass:       accessor,
			Actions:    Enable(Sudo).Enable(actions...),
		},
	}
	return
}

func GenPolicy(rand io.Reader,
	orgId, ownerId uuid.UUID, ownerKey crypto.PublicKey, ownerType Type, strength crypto.Strength, actions ...Action) (policy PolicyLock, err error) {

	policy, secret, err := GenPolicyUnsafe(rand, orgId, ownerId, ownerKey, ownerType, strength, actions...)
	if err != nil {
		return
	}
	defer crypto.Bytes(secret).Destroy()
	return
}

func (p Policy) GetOrgId() uuid.UUID {
	return p.OrgId
}

func (p Policy) GetPolicyId() uuid.UUID {
	return p.Id
}

func (p Policy) GetPublicKey() crypto.PublicKey {
	return p.Key.Pub
}

func (p Policy) Update(fn func(*Policy)) (ret Policy) {
	ret = p
	fn(&ret)
	ret.Updated = time.Now().UTC()
	ret.Version = p.Version + 1
	return
}

func (p Policy) RecoverSecret(rand io.Reader, caller PolicyMember, priv crypto.PrivateKey) (ret []byte, err error) {
	pass, err := caller.Decrypt(rand, priv)
	if err != nil {
		err = errors.Wrapf(err, "Error decrypting membership pass")
		return
	}

	ret, err = p.Secret.Decrypt(pass)
	return
}

func (p Policy) RecoverPrivateKey(rand io.Reader, caller PolicyMember, priv crypto.PrivateKey) (ret crypto.PrivateKey, err error) {
	pass, err := caller.Decrypt(rand, priv)
	if err != nil {
		err = errors.Wrapf(err, "Error decrypting membership pass")
		return
	}

	ret, err = p.Key.Decrypt(enc.Json, pass)
	return
}

func (p Policy) AddMember(rand io.Reader, caller PolicyMember, callerKey crypto.PrivateKey, memberId uuid.UUID, memberType Type, memberKey crypto.PublicKey, actions ...Action) (ret PolicyMember, err error) {
	pass, err := caller.Decrypt(rand, callerKey)
	if err != nil {
		return
	}

	accessor, err := GenMemberSecret(rand, memberKey, pass, p.Strength)
	if err != nil {
		return
	}

	now := time.Now().UTC()
	ret = PolicyMember{
		OrgId:      p.OrgId,
		PolicyId:   p.Id,
		MemberType: memberType,
		MemberId:   memberId,
		Created:    now,
		Updated:    now,
		Pass:       accessor,
		Actions:    Unflatten(actions),
	}
	return
}

type PolicyMember struct {
	OrgId      uuid.UUID    `json:"org_id"`
	PolicyId   uuid.UUID    `json:"policy_id"`
	MemberType Type         `json:"member_type"`
	MemberId   uuid.UUID    `json:"member_id"`
	MemberVer  int          `json:"member_int"`
	Version    int          `json:"version"`
	Deleted    bool         `json:"deleted"`
	Created    time.Time    `json:"created"`
	Updated    time.Time    `json:"updated"`
	Actions    Actions      `json:"actions"`
	Pass       MemberSecret `json:"pass"`
}

func (p PolicyMember) Update(fn func(*PolicyMember)) (ret PolicyMember) {
	ret = p
	fn(&ret)
	ret.Updated = time.Now().UTC()
	ret.Version = p.Version + 1
	if ret.Actions.Enabled(Sudo) {
		ret.Actions = Enable(Sudo)
	}
	return
}

func (p PolicyMember) Decrypt(rand io.Reader, priv crypto.PrivateKey) (ret []byte, err error) {
	ret, err = p.Pass.Decrypt(rand, priv)
	return
}

func (p PolicyMember) Restore(actions ...Action) (ret PolicyMember) {
	ret = p.Update(func(n *PolicyMember) {
		n.Deleted = false
		n.Actions = Unflatten(actions)
	})
	return
}

func (p PolicyMember) Delete() (ret PolicyMember) {
	ret = p.Update(func(n *PolicyMember) {
		n.Deleted = true
	})
	return
}

func (p PolicyMember) GetOrgId() (ret uuid.UUID) {
	ret = p.OrgId
	return
}

func (p PolicyMember) GetPolicyId() (ret uuid.UUID) {
	ret = p.PolicyId
	return
}

// A crumb is left for the recipient to decrypt using their
// private signing key.
type MemberSecret struct {
	Key  crypto.KeyExchange      `json:"key"`
	Data crypto.SaltedCipherText `json:"data"`
}

func GenMemberSecret(rand io.Reader, pub crypto.PublicKey, secret []byte, strength crypto.Strength) (ret MemberSecret, err error) {
	exchg, key, err := strength.GenKeyExchange(rand, pub)
	if err != nil {
		return
	}
	defer crypto.Bytes(key).Destroy()

	ct, err := strength.SaltAndEncrypt(rand, key, secret)
	if err != nil {
		return
	}

	ret = MemberSecret{exchg, ct}
	return
}

// Decrypts the crumb and returns the raw secret
func (p MemberSecret) Decrypt(rand io.Reader, priv crypto.PrivateKey) (ret []byte, err error) {
	key, err := p.Key.DecryptKey(rand, priv)
	if err != nil {
		return
	}

	ret, err = p.Data.Decrypt(key)
	return
}
