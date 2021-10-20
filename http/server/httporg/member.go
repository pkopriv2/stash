package httporg

import (
	client "github.com/cott-io/stash/http/client/httporg"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/libs/page"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func MemberHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/orgs/{id}/members"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, accts, db :=
				core.AssignSigner(env),
				core.AssignAccounts(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "id", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var r client.CreateMemberRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsMember(orgId,
					auth.Max(auth.Manager,
						auth.Min(auth.Owner, r.Role+1)))); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			settings, exists, err := accts.LoadSettings(r.AcctId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists || !settings.Enabled {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such account [%v]", r.AcctId))
				return
			}

			_, exists, err = db.LoadOrgById(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			if err := db.SaveMember(org.NewMember(orgId, r.AcctId, r.Role)); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return

		})

	svc.Register(http.Put("/v1/orgs/{orgId}/members/{acctId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var orgId, acctId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("acctId", http.UUID, &acctId),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var r client.UpdateMemberRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsNotAccount(acctId),
				auth.IsMember(orgId,
					auth.Max(auth.Manager,
						auth.Min(auth.Owner, r.Role+1)))); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			member, exists, err := db.LoadMember(orgId, acctId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists {
				ret = http.NotFound(errors.Wrapf(org.ErrNoMember, "No such member [%v] in org [%v]", acctId, orgId))
				return
			}

			if err := db.SaveMember(member.Update(org.MemberUpdateRole(r.Role))); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return

		})

	svc.Register(http.Delete("/v1/orgs/{orgId}/members/{acctId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var orgId, acctId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("acctId", http.UUID, &acctId),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			member, exists, err := db.LoadMember(orgId, acctId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists {
				ret = http.NotFound(errors.Wrapf(org.ErrNoMember, "No such member [%v] in org [%v]", acctId, orgId))
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsNotAccount(acctId),
				auth.IsMember(orgId,
					auth.Max(auth.Manager,
						auth.Min(auth.Owner, member.Role+1)))); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			if err := db.SaveMember(member.Update(org.MemberDelete)); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return

		})

	svc.Register(http.Get("/v1/orgs/{orgId}/members/{acctId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var orgId, acctId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("acctId", http.UUID, &acctId),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			member, exists, err := db.LoadMember(orgId, acctId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists {
				ret = http.NotFound(errors.Wrapf(org.ErrNoMember, "No such member [%v] in org [%v]", acctId, orgId))
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, member))
			return

		})

	svc.Register(http.Get("/v1/orgs/{orgId}/members"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var offset, limit *uint64
			if err := http.ParseQueryParams(req,
				http.Param("offset", http.Uint64, &offset),
				http.Param("limit", http.Uint64, &limit),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			members, err := db.ListMembers(org.BuildFilter(org.FilterByOrgId(orgId)),
				page.BuildPage(
					page.OffsetPtr(offset),
					page.LimitPtr(limit)))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, members))
			return

		})

	svc.Register(http.Get("/v1/accounts/{acctId}/members"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var acctId uuid.UUID
			if err := http.RequirePathParam(req, "acctId", http.UUID, &acctId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var offset, limit *uint64
			if err := http.ParseQueryParams(req,
				http.Param("offset", http.Uint64, &offset),
				http.Param("limit", http.Uint64, &limit),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsAccount(acctId)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			members, err := db.ListMembers(org.BuildFilter(org.FilterByAccountId(acctId)),
				page.BuildPage(
					page.OffsetPtr(offset),
					page.LimitPtr(limit)))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, members))
			return

		})
}

//var OrgPurchaseTemplate = msgs.BuildTemplate(
//"Congratulations on your new org!",

//msgs.AsMicro(`
//You've purchased a new org {{.Org}}!
//`),

//msgs.AsText(`
//Congratulations on your new org {{.Org}}!

//To get started, start inviting others:

//fe org invite {{.Org}} friend@example.com

//Not You?

//If this is not you, please contact:

//support@cott.io

//`),

//msgs.AsMarkdown(`
//# Congratulations!

//You have successfully purchased a subscription to {{.Org}}.

//### Plan Details

//* Org:           {{.Org}}
//* Email:         {{.Purchase.Email}}
//* Users:         {{.Purchase.Users}}
//* Agents:        {{.Purchase.Agents}}

//### Next Steps

//* Start inviting others:

//fe org invite {{.Org}} friend@example.com

//* Start viewing your invoices:

//fe org plan ls {{.Org}}

//* Cancel your subscription:

//fe org plan rm {{.Org}}

//### Not You?

//If this is not you, please contact:

//support@cott.io

//`))

//func NewOrgPurchaseMessage(on string, purchase org.Purchase) msgs.Message {
//return msgs.Compile(OrgPurchaseTemplate, *purchase.Email, struct {
//Org      string
//Purchase org.Purchase
//}{
//on,
//purchase,
//})
//}
