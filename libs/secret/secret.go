package secret

import (
	"fmt"
	"strings"
	"time"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/policy"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	ErrNoSecret = errors.New("Secret:NoSecret")
)

var (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers = "0123456789"
	symbols = "./-_"
)

// A secret name must conform to the following rules:
//
// 1. Begin with a '/' or dot '.'
// 2. Contain only letters (a-zA-Z), numbers (0-9), dashes '-'
//    underscores '_', slashes '/' or dots '.'
// 3. A secret beginning with a dot (.) is considered hidden
//    and is not listed in standard listings.
//
func VerifyName(str string) (err error) {
	runes := []rune(str)
	if len(runes) == 0 {
		err = errors.Wrapf(errs.ArgError, "Secret names must not be empty")
		return
	}
	switch runes[0] {
	default:
		err = errors.Wrapf(errs.ArgError, "Invalid secret name [%v]. Must begin with a '/' or a '.'", str)
		return
	case '.', '/':
	}

	for _, r := range runes[1:] {
		if strings.IndexRune(letters, r) >= 0 {
			continue
		}
		if strings.IndexRune(numbers, r) >= 0 {
			continue
		}
		if strings.IndexRune(symbols, r) >= 0 {
			continue
		}

		err = errors.Wrapf(errs.ArgError, "Invalid secret name [%v]. Secret names may only contain [a-zA-Z0-9./-_]", str)
		return
	}
	return
}

const (
	Restore = "restore"
)

func ParseAction(str string) (ret policy.Action, err error) {
	switch strings.TrimSpace(str) {
	default:
		err = errors.Wrapf(policy.ErrNotAnAction, "Invalid action [%v]", str)
	case string(policy.View):
		ret = policy.View
	case string(policy.Edit):
		ret = policy.Edit
	case string(policy.Delete):
		ret = policy.Delete
	case Restore:
		ret = Restore
	}
	return
}

type SecretSummary struct {
	Secret  `json:"secret"`
	Actions policy.Actions `json:"actions"`
}

func ToSecretSummaries(all []Secret) (ret []SecretSummary) {
	for _, s := range all {
		ret = append(ret, SecretSummary{Secret: s})
	}
	return
}

// Joins the tags on to the collection of secrets.
func DecorateSecrets(policies policy.Storage, userId uuid.UUID, secrets ...Secret) (ret []SecretSummary, err error) {
	if len(secrets) == 0 {
		ret = []SecretSummary{}
		return
	}

	var secretIds, policyIds []uuid.UUID
	for _, b := range secrets {
		secretIds, policyIds =
			append(secretIds, b.Id),
			append(policyIds, b.PolicyId)
	}

	actions, err := policies.LoadEnabledActions(secrets[0].OrgId, userId, policyIds...)
	if err != nil {
		return
	}

	for _, s := range secrets {
		ret = append(ret, SecretSummary{Secret: s, Actions: actions[s.PolicyId]})
	}
	return
}

type Secret struct {
	Id          uuid.UUID        `json:"id"`
	OrgId       uuid.UUID        `json:"org_id"`
	PolicyId    uuid.UUID        `json:"policy_id"`
	StreamId    uuid.UUID        `json:"stream_id"`
	StreamSize  int              `json:"stream_size"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Type        string           `json:"type"`
	Version     int              `json:"version"`
	Created     time.Time        `json:"created"`
	Updated     time.Time        `json:"updated"`
	Expires     time.Duration    `json:"expires"`
	Expired     bool             `json:"expired"`
	Deleted     bool             `json:"deleted"`
	Salt        crypto.Salt      `json:"salt" sql:"salt,string"`
	AuthorId    uuid.UUID        `json:"author_id"`
	AuthorSig   crypto.Signature `json:"author_sig" sql:"author_sig,string"`
	Comment     string           `json:"comment"`
}

func (b Secret) Format() string {
	return fmt.Sprintf("%v://%v", "secret", b.Name)
}

func (b Secret) FormatUUID() string {
	return fmt.Sprintf("%v://%v", "secret", b.Id)
}

func (b Secret) GetOrgId() uuid.UUID {
	return b.OrgId
}

func (b Secret) GetPolicyId() uuid.UUID {
	return b.PolicyId
}

func (b Secret) DeriveKey(cipher crypto.Cipher, key []byte) (ret []byte) {
	return b.Salt.Apply(key, cipher.KeySize())
}

func (b Secret) Update() (ret Builder) {
	return func(o *Secret) {
		*o = b
		o.Updated = time.Now().UTC()
		o.Version = b.Version + 1
	}
}

type Block struct {
	OrgId    uuid.UUID         `json:"org_id"`
	StreamId uuid.UUID         `json:"stream_id"`
	Idx      int               `json:"idx"`
	Data     crypto.CipherText `json:"data" sql:data,string`
}

func (b Block) Decrypt(key []byte) (ret []byte, err error) {
	return b.Data.Decrypt(key)
}

type Builder func(*Secret)

func NewSecret() Builder {
	return func(b *Secret) {}
}

func (b Builder) And(fn func(*Secret)) Builder {
	return func(o *Secret) {
		b(o)
		fn(o)
	}
}

func (b Builder) SetOrg(orgId uuid.UUID) Builder {
	return b.And(func(b *Secret) {
		b.OrgId = orgId
	})
}

func (b Builder) SetDeleted(del bool) Builder {
	return b.And(func(b *Secret) {
		b.Deleted = del
	})
}

func (b Builder) SetPolicy(policyId uuid.UUID) Builder {
	return b.And(func(b *Secret) {
		b.PolicyId = policyId
	})
}

func (b Builder) SetName(name string) Builder {
	return b.And(func(b *Secret) {
		b.Name = name
	})
}

func (b Builder) SetDesc(desc string) Builder {
	return b.And(func(b *Secret) {
		b.Description = desc
	})
}

func (b Builder) SetType(typ string) Builder {
	return b.And(func(b *Secret) {
		b.Type = typ
	})
}

func (b Builder) SetAuthor(id uuid.UUID, sig crypto.Signature) Builder {
	return b.And(func(b *Secret) {
		b.AuthorId = id
		b.AuthorSig = sig
	})
}

func (b Builder) SetSalt(salt crypto.Salt) Builder {
	return b.And(func(b *Secret) {
		b.Salt = salt
	})
}

func (b Builder) SetStream(stream uuid.UUID, size int) Builder {
	return b.And(func(b *Secret) {
		b.StreamId = stream
		b.StreamSize = size
	})
}

func (b Builder) SetComment(cmmt string) Builder {
	return b.And(func(b *Secret) {
		b.Comment = cmmt
	})
}

func (b Builder) SetExpires(ttl time.Duration) Builder {
	return b.And(func(b *Secret) {
		b.Expires = ttl
	})
}

func (b Builder) SetExpired(ttl time.Duration) Builder {
	return b.And(func(b *Secret) {
		now := time.Now().UTC()
		exp := time.Now().Add(ttl).UTC()
		b.Expired = exp.Before(now)
	})
}

func (b Builder) Compile() (ret Secret, err error) {
	now := time.Now().UTC()
	ret = Secret{
		Id:      uuid.NewV4(),
		Created: now,
		Updated: now,
	}
	b(&ret)

	err = VerifyName(ret.Name)
	return
}

func (b Builder) MustCompile() (ret Secret) {
	ret, err := b.Compile()
	if err != nil {
		panic(err)
	}
	return
}
