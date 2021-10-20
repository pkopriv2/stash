package httporg

import (
	"strings"

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

func OrgHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/orgs"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, biller, db :=
				core.AssignSigner(env),
				core.AssignBiller(env),
				core.AssignOrgs(env)

			var r client.PurchaseRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			name := strings.ToLower(strings.Trim(r.Name, " "))
			if name == "private" {
				ret = http.BadRequest(errors.New("Cannot buy 'private' orgs"))
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgs, err := db.ListOrgs(org.BuildFilter(org.FilterByName(name)), page.BuildPage(page.Limit(1)))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if len(orgs) > 0 {
				ret = http.Conflict(errors.Wrapf(org.ErrOrgExists, "Org already exists [%v]", r.Name))
				return
			}

			if ret = http.NotNil(r.Purchase.Payment, "Missing required payment"); ret != nil {
				return
			}

			if ret = http.First(
				http.NotNil(r.Purchase.Payment.Token, "Missing required payment token"),
				http.NotNil(r.Purchase.Email, "Missing required email"),
				http.NotNil(r.Purchase.Users, "Missing required users"),
				http.NotNil(r.Purchase.Agents, "Missing required agents")); ret != nil {
				return
			}

			customer, err := biller.NewCustomer(*r.Purchase.Email, *r.Purchase.Payment.Token)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			subId, err := biller.NewSubscription(customer.Id, r.Purchase.Items())
			if err != nil {
				ret = http.Panic(err)
				return
			}

			claim, err := auth.ParseClaims(req, signer.Public())
			if err != nil {
				ret = http.Panic(err)
				return
			}

			orgn := org.NewOrg(name)
			memb := org.NewMember(orgn.Id, claim.Account.Id, auth.Owner)
			subs := org.NewSubscription(
				orgn.Id,
				*r.Purchase.Email,
				*r.Purchase.Users,
				*r.Purchase.Agents,
				org.Stripe,
				subId,
				customer.Id)

			if err := db.CreateOrg(orgn, subs, memb); err != nil {
				ret = http.Panic(err)
				return
			}

			env.Logger().Info("Successfully created subscription [%v] for payer [%v]", subId, customer.Id)
			//if err = msg.Send(env, msg.Mailer, NewOrgPurchaseMessage(r.Org, r.Purchase)); err != nil {
			//env.Logger().Error("Error sending purchase message to [%v]: %v", r.Purchase.Email, err)
			//// this doesn't constitute a failure.
			//}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, orgn))
			return

		})

	svc.Register(http.Post("/v1/orgs_list"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var r client.ListRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgs, err := db.ListOrgs(
				org.BuildFilter(org.FilterByOrgIds(r.Ids...)),
				page.BuildPage(page.Limit(uint64(len(r.Ids)))))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, orgs))
			return
		})

	svc.Register(http.Get("/v1/orgs"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var name string
			if err := http.RequireQueryParam(req, "name", http.String, &name); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgs, err := db.ListOrgs(org.BuildFilter(org.FilterByName(name)), page.BuildPage(page.Limit(1)))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if len(orgs) == 0 {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", name))
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, orgs[0]))
			return
		})

	svc.Register(http.Get("/v1/orgs/{id}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "id", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgs, err := db.ListOrgs(org.BuildFilter(org.FilterByOrgIds(orgId)), page.BuildPage(page.Limit(1)))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if len(orgs) == 0 {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, orgs[0]))
			return

		})

	svc.Register(http.Put("/v1/orgs/{id}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "id", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var orgn org.Org
			if err := http.RequireStruct(req, enc.DefaultRegistry, &orgn); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.AssertTrue(orgId == orgn.Id, "Inconsistent org ids"); ret != nil {
				return
			}
			if ret = http.AssertTrue(orgn.Deleted, "Cannot delete orgs.  Must cancel subscription"); ret != nil {
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Owner)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			_, exists, err := db.LoadOrgById(orgId)
			if err != nil {
				http.Panic(err)
				return
			}
			if !exists {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			if err := db.SaveOrg(orgn); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
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
