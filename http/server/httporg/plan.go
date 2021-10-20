package httporg

import (
	client "github.com/cott-io/stash/http/client/httporg"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func PlanHandlers(svc *http.Service) {
	svc.Register(http.Get("/v1/subscriptions/{orgId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, biller, orgs :=
				core.AssignSigner(env),
				core.AssignBiller(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Owner)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgn, exists, err := orgs.LoadOrgById(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists || orgn.Deleted {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			sub, ok, err := orgs.LoadSubscription(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.StatusNotFound
				return
			}

			//total, agents, err := orgs.ActiveMemberCount(orgId)
			//if err != nil {
			//ret = http.Panic(err)
			//return
			//}

			cus, ok, err := biller.GetCustomer(sub.XCustomerId)
			if err != nil || !ok {
				ret = http.Panic(err)
				return
			}

			pend, err := biller.NextInvoice(cus.Id, sub.XSubId)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json,
					org.SubscriptionSummary{
						Subscription: sub,
						NextInvoice:  pend,
						Card:         cus.Payment.Card}))
			return

		})

	svc.Register(http.Put("/v1/subscriptions/{orgId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, biller, orgs :=
				core.AssignSigner(env),
				core.AssignBiller(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var r client.UpdateSubscriptionRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Owner)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgn, exists, err := orgs.LoadOrgById(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists || orgn.Deleted {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			sub, ok, err := orgs.LoadSubscription(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if !ok {
				ret = http.NotFound(errors.Wrapf(org.ErrNoSubscription, "Such such subcription [%v]", orgId))
				return
			}

			// We are taking the approach that any property may be updated on the subscription.
			// In order to minimize the difference between our external billing system and our
			// internal view of the subscription, we're going to save each update independently
			if r.Purchase.Payment != nil {
				if err = biller.UpdateCustomer(billing.Customer{Id: sub.XCustomerId, Payment: *r.Purchase.Payment}); err != nil {
					ret = http.Panic(errors.Wrapf(err, "Error updating payment info.  Please try again to complete"))
					return
				}
			}

			if r.Purchase.Email != nil {
				if err = biller.UpdateCustomer(billing.Customer{Id: sub.XCustomerId, Email: *r.Purchase.Email}); err != nil {
					ret = http.Panic(err)
					return
				}

				sub = sub.Update(org.UpdateEmail(*r.Purchase.Email))
				if err = orgs.SaveSubscription(sub); err != nil {
					ret = http.Panic(errors.Wrapf(err, "Partial update occurred.  Please try again to complete"))
					return
				}
			}

			if items := r.Purchase.Items(); len(items) > 0 {
				if err = biller.UpdateSubscription(sub.XSubId, r.Purchase.Items()); err != nil {
					ret = http.Panic(err)
					return
				}

				updates := []func(*org.Subscription){}
				if r.Purchase.Users != nil {
					if *r.Purchase.Users < 1 {
						ret = http.BadRequest(errors.Wrapf(org.ErrNoUsers, "Must have at least one user"))
						return
					}
					updates = append(updates, org.UpdateUsers(*r.Purchase.Users))
				}

				if r.Purchase.Agents != nil {
					updates = append(updates, org.UpdateAgents(*r.Purchase.Agents))
				}

				if err = orgs.SaveSubscription(sub.Update(updates...)); err != nil {
					ret = http.Panic(errors.Wrapf(err, "Partial update occurred.  Please try again to complete"))
					return
				}
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Delete("/v1/subscriptions/{orgId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, biller, orgs :=
				core.AssignSigner(env),
				core.AssignBiller(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Owner)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgn, exists, err := orgs.LoadOrgById(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists || orgn.Deleted {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			sub, ok, err := orgs.LoadSubscription(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.StatusNotFound
				return
			}

			if err = biller.CancelSubscription(sub.XSubId); err != nil {
				ret = http.Panic(errors.Wrapf(err, "Error canceling on our 3rd party processing system. Please try again."))
				return
			}

			if err = orgs.SaveOrg(orgn.Update(org.OrgDelete)); err != nil {
				ret = http.Panic(err)
				return
			}

			//defer func() {
			//customer, ok, err := billing.GetCustomer(sub.XCustomerId)
			//if err != nil || !ok {
			//env.Logger().Error("Unable to load customer [%v]", sub.XCustomerId)
			//return
			//}

			//if err = msg.Send(env, msg.Mailer, NewOrgCancelMessage(customer.Email, orgn.Name)); err != nil {
			//env.Logger().Error("Error sending cancellation message [%v]", sub.XCustomerId)
			//return
			//}
			//}()

			ret = http.StatusNoContent
			return

		})

	svc.Register(http.Get("/v1/subscriptions/{orgId}/invoices"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, biller, orgs :=
				core.AssignSigner(env),
				core.AssignBiller(env),
				core.AssignOrgs(env)

			var orgId uuid.UUID
			if err := http.RequirePathParam(req, "orgId", http.UUID, &orgId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var limit int64
			if _, err := http.ParseQueryParam(req, "limit", http.Int64, &limit); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsMember(orgId, auth.Owner)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			orgn, exists, err := orgs.LoadOrgById(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists || orgn.Deleted {
				ret = http.NotFound(errors.Wrapf(org.ErrNoOrg, "No such org [%v]", orgId))
				return
			}

			sub, ok, err := orgs.LoadSubscription(orgId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.NotFound(errors.Wrapf(org.ErrNoSubscription, "No such subscription [%v]", orgId))
				return
			}

			all, err := biller.ListInvoices(sub.XSubId, nil, limit)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, all))
			return
		})
}
