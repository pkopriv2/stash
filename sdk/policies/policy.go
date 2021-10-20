package policies

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func CreatePolicy(s session.Session, orgId uuid.UUID, strength crypto.Strength, actions ...policy.Action) (ret policy.PolicyLock, err error) {
	ret, err = policy.GenPolicy(crypto.Rand, orgId, s.AccountId(), s.Secret().PublicKey(), policy.UserType, strength, actions...)
	if err != nil {
		return
	}

	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	err = s.Options().Policies().CreatePolicy(token, ret.Core, ret.CoreMember)
	return
}

func RequirePolicyById(s session.Session, orgId, policyId uuid.UUID) (ret policy.Policy, err error) {
	ret, ok, err := LoadPolicyById(s, orgId, policyId)
	if !ok {
		err = errs.Or(err, errors.Wrapf(policy.ErrNoPolicy, "Not a policy [%v]", policyId))
	}
	return
}

func LoadPolicyById(s session.Session, orgId, policyId uuid.UUID) (ret policy.Policy, ok bool, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, ok, err = s.Options().Policies().LoadPolicy(token, orgId, policyId)
	return
}

func SavePolicyMember(s session.Session, m policy.PolicyMember) (err error) {
	token, err := s.FetchToken(auth.WithOrgId(m.OrgId))
	if err != nil {
		return
	}

	err = s.Options().Policies().SavePolicyMember(token, m)
	return
}

func RequirePolicyMember(s session.Session, orgId, policyId, memberId uuid.UUID) (ret policy.PolicyMember, err error) {
	ret, ok, err := LoadPolicyMember(s, orgId, policyId, memberId)
	if !ok {
		err = errs.Or(err, errors.Wrapf(policy.ErrNotAMember, "Not a member of policy [%v]", policyId))
	}
	return
}

func LoadPolicyMember(s session.Session, orgId, policyId, memberId uuid.UUID) (ret policy.PolicyMember, ok bool, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, ok, err = s.Options().Policies().LoadPolicyMember(token, orgId, policyId, memberId)
	return
}

func ListPolicyMembers(s session.Session, orgId, policyId uuid.UUID, opt ...page.PageOption) (ret []policy.PolicyMemberInfo, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, err = s.Options().Policies().ListPolicyMembers(token, orgId, policyId, page.BuildPage(opt...))
	return
}

func RequirePolicyLock(s session.Session, orgId, policyId, memberId uuid.UUID) (ret policy.PolicyLock, err error) {
	ret, ok, err := LoadPolicyLock(s, orgId, policyId, memberId)
	if !ok {
		err = errs.Or(err, errors.Wrapf(policy.ErrNotAMember, "Unauthorized"))
	}
	return
}

func LoadPolicyLock(s session.Session, orgId, policyId, memberId uuid.UUID) (ret policy.PolicyLock, ok bool, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, ok, err = s.Options().Policies().LoadPolicyLock(token, orgId, policyId, memberId)
	return
}

func GrantPolicyMember(s session.Session, lock policy.PolicyLock, memberType MemberType, memberId uuid.UUID, actions ...policy.Action) (err error) {
	priv, err := s.Secret().RecoverKey()
	if err != nil {
		return
	}
	defer priv.Destroy()

	pub, err := memberType.GetPublicKey(s, lock.OrgId(), memberId)
	if err != nil || pub == nil {
		err = errs.Or(err, errors.Wrapf(errs.StateError, "Unable to download public key [%v]", memberId))
		return
	}

	member, err := lock.AddMember(crypto.Rand, priv, memberId, memberType.Type(), pub, actions...)
	if err != nil {
		return
	}

	err = SavePolicyMember(s, member)
	return
}

func RevokePolicyMember(s session.Session, lock policy.PolicyLock, memberId uuid.UUID, actions ...policy.Action) (err error) {

	// A membership may alread exist for this user, but in the deleted state.
	orig, ok, err := LoadPolicyMember(s, lock.OrgId(), lock.Id(), memberId)
	if !ok {
		err = errs.Or(err, errors.Wrapf(policy.ErrNotAMember, "Not currently a member"))
		return
	}

	updated := orig.Restore(orig.Actions.Disable(actions...).Flatten()...)
	if len(actions) == 0 {
		updated = orig.Delete()
	}

	err = SavePolicyMember(s, updated)
	return
}

func IsAuthorized(s session.Session, orgId, policyId, memberId uuid.UUID, any ...policy.Action) (ok bool, err error) {
	member, ok, err := LoadPolicyMember(s, orgId, policyId, memberId)
	if err != nil || !ok {
		return
	}

	if member.Actions.Enabled(policy.Sudo) {
		ok = true
		return
	}

	for _, a := range any {
		if member.Actions.Enabled(a) {
			ok = true
		}
	}
	return
}
