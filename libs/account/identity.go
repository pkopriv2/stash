package account

import (
	"time"

	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
)

func LookupDisplays(identsByAcccountIds map[uuid.UUID][]Identity) (ret map[uuid.UUID]Identity) {
	ret = make(map[uuid.UUID]Identity)
	for acctId, ids := range identsByAcccountIds {
		ret[acctId] = LookupDisplay(ids)
	}
	return
}

func LookupDisplay(ids []Identity) (ret Identity) {
	for _, id := range ids {
		if id.Verified && auth.Weight(id.Id) > auth.Weight(ret.Id) {
			ret = id
		}
	}
	return
}

func LookupPrimaryEmail(ids []Identity) (ret Identity, found bool) {
	for _, id := range ids {
		if id.Id.Proto != auth.Email || !id.Verified {
			continue
		}
		if !found {
			ret, found = id, true
			continue
		}
		if id.Created.Before(ret.Created) {
			ret = id
		}
	}
	return
}

func LookupPrimaryPhone(ids []Identity) (ret Identity, found bool) {
	for _, id := range ids {
		if id.Id.Proto != auth.Phone || !id.Verified {
			continue
		}
		if !found {
			ret, found = id, true
			continue
		}
		if id.Created.Before(ret.Created) {
			ret = id
		}
	}
	return
}

func IdentityDelete(cur *Identity) (err error) {
	cur.Deleted = true
	return
}

func IdentityReset(acctId uuid.UUID, verifier []byte, opts auth.IdentityOptions) func(*Identity) error {
	return func(cur *Identity) (err error) {
		cur.Deleted = false
		cur.Verifier = verifier
		cur.Verified = verifier == nil
		cur.AccountId = acctId
		cur.LastReason = ""
		cur.LastAttempt = 0
		return
	}
}

func IdentityVerify(attmpt auth.Attempt) func(*Identity) error {
	return func(cur *Identity) (err error) {
		auth, err := cur.ExtractVerifier()
		if err != nil {
			cur.Verified = false
			cur.LastReason = err.Error()
			cur.LastAttempt++
			return
		}

		if err = auth.Validate(attmpt); err != nil {
			cur.Verified = false
			cur.LastReason = err.Error()
			cur.LastAttempt++
			return
		}

		cur.Verified = true
		cur.Verifier = nil
		cur.LastReason = ""
		cur.LastAttempt = 0
		return
	}
}

// An account identity represents the "root" of the account's identity verification.
type Identity struct {
	AccountId   uuid.UUID     `json:"account_id"`
	Id          auth.Identity `json:"id"`
	Uri         string        `json:"uri"`
	Deleted     bool          `json:"deleted"`
	Version     int           `json:"version"`
	Verifier    []byte        `json:"-"` // nillable
	Verified    bool          `json:"verified"`
	LastAttempt int           `json:"-"`
	LastReason  string        `json:"-"`
	Created     time.Time     `json:"created"`
	Updated     time.Time     `json:"updated"`
	Private     bool          `json:"-"`
	DeviceId    string        `json:"-"`
}

func NewIdentity(acctId uuid.UUID, id auth.Identity, verifier auth.Authenticator, opts auth.IdentityOptions) (ret Identity, err error) {
	var raw []byte
	if verifier != nil {
		raw, err = auth.EncodeAuth(enc.Json, verifier)
		if err != nil {
			return
		}
	}

	now := time.Now()
	ret = Identity{
		AccountId: acctId,
		Id:        id,
		Uri:       id.Uri(),
		Deleted:   false,
		Verifier:  raw,
		Verified:  verifier == nil,
		Created:   now.UTC(),
		Updated:   now.UTC(),
		Private:   opts.Private,
		DeviceId:  opts.DeviceId,
	}
	return
}

func (i Identity) ExtractVerifier() (auth.Authenticator, error) {
	return auth.DecodeAuth(enc.Json, i.Verifier)
}

func (i Identity) Update(fns ...func(*Identity) error) (ret Identity, err error) {
	ret = i
	for _, fn := range fns {
		if err = fn(&ret); err != nil {
			return
		}
	}
	ret.Version = i.Version + 1
	ret.Updated = time.Now().UTC()
	return
}

func (i Identity) Info() Identity {
	return Identity{
		Id:        i.Id,
		AccountId: i.AccountId,
		Verified:  i.Verified,
		Created:   i.Created,
		Updated:   i.Updated,
	}
}
