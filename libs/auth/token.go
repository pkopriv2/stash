package auth

import (
	"time"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/http/headers"
	"github.com/cott-io/stash/lang/http/jwt"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	ErrTokenExpired   = errors.New("Auth:ErrTokenExpired")
	ErrTokenInvalid   = errors.New("Auth:ErrTokenInvalid")
	ErrTokenSignature = errors.New("Auth:ErrTokenSignature")
	ErrUnauthorized   = errors.New("Auth:ErrUnauthorized")
)

type Token string

func (t Token) String() string {
	return string(t)
}

type SignedToken struct {
	Token   Token        `json:"token"`
	Account AccountToken `json:"account"`
	Member  MemberToken  `json:"member,omitempty"`
}

func (s SignedToken) Expires() time.Time {
	return time.Unix(s.Account.Expires, 0)
}

func (s SignedToken) String() string {
	return s.Token.String()
}

type AccountToken struct {
	Id           uuid.UUID `json:"id"`
	Identity     Identity  `json:"identity"`
	Expires      int64     `json:"expires"`
	LoginUri     string    `json:"login_uri"`
	LoginVersion int       `json:"login_version"`
}

func (c AccountToken) Expired(now time.Time) bool {
	return time.Unix(c.Expires, 0).Before(now)
}

type MemberToken struct {
	OrgId uuid.UUID `json:"org_id"`
	Role  Role      `json:"role"`
}

func SignClaims(signer crypto.Signer, fn Builder) (ret SignedToken, err error) {
	claim := buildClaim(fn)

	sig, err := jwt.IssueToken(signer, &claim)
	if err != nil {
		return
	}

	ret = SignedToken{Token(sig), claim.Account, claim.Member}
	return
}

type Builder func(*Claim)

func (b Builder) Amend(fns ...Builder) Builder {
	return BuildClaim(append([]Builder{b}, fns...)...)
}

func buildClaim(fn Builder) (c Claim) {
	fn(&c)
	return
}

// Composes a new builder that sequentially calls
// each input function.
func BuildClaim(fns ...Builder) Builder {
	return func(c *Claim) {
		for _, fn := range fns {
			fn(c)
		}
	}
}

func ClaimLogin(uri string, ver int) Builder {
	return func(c *Claim) {
		c.Account.LoginUri = uri
		c.Account.LoginVersion = ver
	}
}

func ClaimExpires(ttl time.Duration) Builder {
	return func(c *Claim) {
		c.Account.Expires = time.Now().Add(ttl).Unix()
	}
}

func ClaimAccount(ident Identity, id uuid.UUID) Builder {
	return func(c *Claim) {
		c.Account.Id = id
		c.Account.Identity = ident
	}
}

func ClaimMember(orgId uuid.UUID, role Role) Builder {
	return func(c *Claim) {
		c.Member.OrgId = orgId
		c.Member.Role = role
	}
}

type Claim struct {
	Account AccountToken `json:"account"`
	Member  MemberToken  `json:"member,omitempty"`
}

func (c Claim) Valid() error {
	return nil
}

func Assert(cond bool, fmt string, args ...interface{}) (ret error) {
	if !cond {
		ret = errors.Wrapf(ErrUnauthorized, fmt, args...)
		return
	}
	return
}

func ParseClaims(req headers.Headers, pub crypto.PublicKey) (ret Claim, err error) {
	raw, err := jwt.ReadToken(req, pub, &ret)
	if err != nil {
		err = errs.Or(err, errors.Wrapf(ErrTokenInvalid, "Invalid token"))
		return
	}
	ret = *(raw.Claims.(*Claim))
	return
}

func ParseAndAssertClaims(req headers.Headers, pub crypto.PublicKey, fns ...func(Claim) error) (claim Claim, err error) {
	claim, err = ParseClaims(req, pub)
	if err != nil {
		return
	}

	fns = append(fns, IsNotExpired())
	for _, fn := range fns {
		if err = fn(claim); err != nil {
			return
		}
	}
	return
}

func AssertClaims(req headers.Headers, pub crypto.PublicKey, fns ...func(Claim) error) (err error) {
	_, err = ParseAndAssertClaims(req, pub, fns...)
	return
}

func IsNotExpired() func(Claim) error {
	return func(c Claim) (err error) {
		if c.Account.Expired(time.Now()) {
			err = errors.Wrapf(ErrUnauthorized, "Token expired")
		}
		return
	}
}

func IsAccount(acctId uuid.UUID) func(Claim) error {
	return func(c Claim) (err error) {
		if c.Account.Id != acctId {
			err = errors.Wrapf(ErrUnauthorized, "Unexpected account")
		}
		return
	}
}

func IsNotAccount(acctId uuid.UUID) func(Claim) error {
	return func(c Claim) (err error) {
		if c.Account.Id == acctId {
			err = errors.Wrapf(ErrUnauthorized, "Unexpected account")
		}
		return
	}
}

func IsNotIdentity(id Identity) func(Claim) error {
	return func(c Claim) (err error) {
		if c.Account.Identity == id {
			err = errors.Wrapf(ErrUnauthorized, "Unexpected login identity")
		}
		return
	}
}

func IsNotLogin(uri string) func(Claim) error {
	return func(c Claim) (err error) {
		if c.Account.LoginUri == uri {
			err = errors.Wrapf(ErrUnauthorized, "Unexpected login uri")
		}
		return
	}
}

func IsMember(orgId uuid.UUID, role Role) func(Claim) error {
	return func(c Claim) (err error) {
		if c.Member.OrgId != orgId {
			err = errors.Wrapf(ErrUnauthorized, "Missing org membership")
			return
		}
		if c.Member.Role < role {
			err = errors.Wrapf(ErrUnauthorized, "Missing org membership")
		}
		return
	}
}
