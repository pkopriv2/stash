package httppolicy

import (
	client "github.com/cott-io/stash/http/client/httppolicy"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	uuid "github.com/satori/go.uuid"
)

func PolicyHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/orgs/{orgId}/policies"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var r client.SavePolicyRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.First(
				http.NotZero(r.Policy.OrgId, "Missing policy id"),
				http.NotZero(r.Policy.Id, "Missing policy id"),
				http.NotZero(r.Member.OrgId, "Missing member org id"),
				http.NotZero(r.Member.PolicyId, "Missing member policy id"),
				http.NotZero(r.Member.MemberId, "Missing member id"),
				http.AssertTrue(r.Policy.OrgId == r.Member.OrgId,
					"Inconsistent org ids"),
				http.AssertTrue(r.Policy.OrgId == orgId,
					"Inconsistent org ids"),
				http.AssertTrue(r.Policy.Id == r.Member.PolicyId,
					"Inconsistent policy ids"),
			); ret != nil {
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			if err := policies.SavePolicy(r.Policy, r.Member); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/policies/{policyId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId, policyId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("policyId", http.UUID, &policyId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			policy, ok, err := policies.LoadPolicy(orgId, policyId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.StatusNotFound
				return
			}

			ret = http.Ok(enc.Json, policy)
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/policies/{policyId}/lock"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId, policyId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("policyId", http.UUID, &policyId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			claim, err := auth.ParseAndAssertClaims(
				req, signer.Public(), auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			memberId := claim.Account.Id
			if err := http.ParseQueryParams(req,
				http.Param("member_id", http.UUID, &memberId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			lock, ok, err := policies.LoadPolicyLock(orgId, policyId, memberId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.StatusNotFound
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, lock))
			return
		})

	svc.Register(http.Put("/v1/orgs/{orgId}/policies/{policyId}/members/{memberId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId, policyId, memberId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("policyId", http.UUID, &policyId),
				http.Param("memberId", http.UUID, &memberId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var member policy.PolicyMember
			if err := http.RequireStruct(req, enc.DefaultRegistry, &member); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.First(
				http.NotZero(member.OrgId, "Missing org id"),
				http.NotZero(member.PolicyId, "Missing Policy id"),
				http.AssertTrue(member.OrgId == orgId, "Inconsistent org ids"),
				http.AssertTrue(member.PolicyId == policyId, "Inconsistent Policy ids"),
				http.AssertTrue(member.MemberId == memberId, "Inconsistent member ids"),
			); ret != nil {
				return
			}

			claim, err := auth.ParseAndAssertClaims(
				req, signer.Public(), auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			// Verify the recipient is a member of the org!
			if member.MemberType == policy.UserType {
				if _, err := core.RequireOrgMembership(
					core.AssignOrgs(env), orgId, member.MemberId); err != nil {
					ret = http.Unauthorized(err)
					return
				}
			}

			if err := policy.Authorize(policies, claim.Account.Id,
				policy.Has(policy.Sudo),
				policy.Addr(orgId, policyId),
			); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			ret = http.StatusNoContent
			if err := policies.SavePolicyMember(member); err != nil {
				ret = http.Panic(err)
				return
			}
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/policies/{policyId}/members"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId, policyId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("policyId", http.UUID, &policyId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var offset *uint64
			var limit *uint64
			if err := http.ParseQueryParams(req,
				http.Param("offset", http.Uint64, &offset),
				http.Param("limit", http.Uint64, &limit)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			// if err := policy.Authorize(policies, claim.AcctId(),
			// policy.Addr(orgId, policyId)); err != nil {
			// ret = http.Unauthorized(err)
			// return
			// }

			members, err := policies.ListPolicyMembers(orgId, policyId,
				page.Page{
					Offset: offset,
					Limit:  limit,
				})
			if err != nil {
				ret = http.Panic(err)
				return
			}

			var userIds, groupIds []uuid.UUID
			for _, m := range members {
				switch m.MemberType {
				case policy.UserType:
					userIds = append(userIds, m.MemberId)
				case policy.GroupType:
					groupIds = append(groupIds, m.MemberId)
				}
			}

			// FIXME: NEED TO FILTER OUT DELETED ENTITIES!!!
			usersCh, groupsCh, failCh :=
				make(chan map[uuid.UUID]auth.Identity, 1),
				make(chan map[uuid.UUID]string, 1),
				make(chan error, 2)

			go func() {
				ids, err := core.LookupDisplays(core.AssignAccounts(env), userIds)
				if err != nil {
					failCh <- err
					return
				}
				usersCh <- ids
			}()
			go func() {
				names, err := core.LoadGroupNames(policies, orgId, groupIds)
				if err != nil {
					failCh <- err
					return
				}
				groupsCh <- names
			}()

			var users map[uuid.UUID]auth.Identity
			var groups map[uuid.UUID]string
			for i := 0; i < 2; i++ {
				select {
				case err = <-failCh:
					ret = http.Panic(err)
					return
				case users = <-usersCh:
				case groups = <-groupsCh:
				}
			}

			var results []policy.PolicyMemberInfo
			for _, m := range members {
				var u *auth.Identity
				var g *string
				switch m.MemberType {
				case policy.UserType:
					if tmp, ok := users[m.MemberId]; ok {
						u = &tmp
					}
				case policy.GroupType:
					if tmp, ok := groups[m.MemberId]; ok {
						g = &tmp
					}
				}

				results = append(results, policy.PolicyMemberInfo{m, u, g})
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, results))
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/policies/{policyId}/members/{memberId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId, policyId, memberId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("policyId", http.UUID, &policyId),
				http.Param("memberId", http.UUID, &memberId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			claim, err := auth.ParseAndAssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			if err := policy.Authorize(policies, claim.Account.Id,
				policy.Any(),
				policy.Addr(orgId, policyId)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			member, ok, err := policies.LoadPolicyMember(orgId, policyId, memberId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.StatusNotFound
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, member))
			return
		})
}
