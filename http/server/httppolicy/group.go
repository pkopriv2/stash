package httppolicy

import (
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	uuid "github.com/satori/go.uuid"
)

func GroupHandlers(svc *http.Service) {

	svc.Register(http.Put("/v1/orgs/{orgId}/groups/{groupId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId, groupId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("groupId", http.UUID, &groupId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var group policy.Group
			if err := http.RequireStruct(req, enc.DefaultRegistry, &group); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.First(
				http.NotZero(group.OrgId, "Missing org id"),
				http.NotZero(group.Id, "Missing group id"),
				http.NotZero(group.PolicyId, "Missing policy id"),
				http.AssertTrue(group.OrgId == orgId, "Inconsistent org ids"),
				http.AssertTrue(group.Id == groupId, "Inconsistent group ids"),
			); ret != nil {
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			claim, err := auth.ParseClaims(req, signer.Public())
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			var action policy.Action = policy.Edit
			if group.Deleted {
				action = policy.Delete
			}

			if err := policy.Authorize(policies, claim.Account.Id,
				policy.Has(action), group); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			if err := policies.SaveGroup(group); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Post("/v1/orgs/{orgId}/groups_list"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies :=
				core.AssignSigner(env),
				core.AssignPolicies(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
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

			var filter policy.GroupFilter
			if err := http.RequireStruct(req, enc.DefaultRegistry, &filter); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			groups, err := policies.ListGroups(orgId, filter,
				page.Page{
					Offset: offset,
					Limit:  limit,
				})
			if err != nil {
				ret = http.Panic(err)
				return
			}

			claim, err := auth.ParseClaims(req, signer.Public())
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			infos, err := policy.DecorateGroups(policies, claim.Account.Id, groups...)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, infos))
			return
		})
}
