package org

import (
	"time"

	"github.com/cott-io/stash/lang/billing"
	uuid "github.com/satori/go.uuid"
)

type XSystemId string

const (
	Stripe XSystemId = "Stripe"
)

// A couple summary objects
type InvoiceSummary struct {
	billing.Invoice `json:"invoice"`
	Org             string `json:"org"`
}

// The subscription options.
type Purchase struct {
	Email   *string          `json:"email"`
	Users   *int             `json:"users"`
	Agents  *int             `json:"agents"`
	Payment *billing.Payment `json:"payment"`
}

func (p Purchase) Items() (ret []billing.Item) {
	ret = []billing.Item{}
	if p.Users != nil {
		ret = append(ret,
			billing.Item{
				Plan:     billing.Users,
				Quantity: int64(*p.Users),
			})
	}
	if p.Agents != nil {
		ret = append(ret,
			billing.Item{
				Plan:     billing.Agents,
				Quantity: int64(*p.Agents),
			})
	}
	return
}

type PurchaseOption func(*Purchase)

func WithUsers(users int) PurchaseOption {
	return func(a *Purchase) {
		a.Users = &users
	}
}

func WithAgents(agents int) PurchaseOption {
	return func(a *Purchase) {
		a.Agents = &agents
	}
}

func WithEmail(email string) PurchaseOption {
	return func(a *Purchase) {
		a.Email = &email
	}
}

func WithCard(card billing.Card) PurchaseOption {
	return func(a *Purchase) {
		a.Payment = &billing.Payment{
			Card: &card,
		}
	}
}

func WithToken(token string) PurchaseOption {
	return func(a *Purchase) {
		a.Payment = &billing.Payment{
			Token: &token,
		}
	}
}

func intPtr(val int) *int {
	return &val
}

func strPtr(val string) *string {
	return &val
}

func BuildPurchase(fns ...PurchaseOption) (ret Purchase) {
	ret = Purchase{Email: strPtr(""), Users: intPtr(5), Agents: intPtr(5)}
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

// A subscription is a local copy of an externally managed subscription.
type SubscriptionSummary struct {
	Subscription `json:"subscription"`
	Card         *billing.Card   `json:"card"`
	NextInvoice  billing.Invoice `json:"next_invoice"`
	ActiveUsers  int             `json:"active_users"`
	ActiveAgents int             `json:"active_agents"`
}

// A subscription is a local copy of an externally managed subscription.
type Subscription struct {
	Id          uuid.UUID `json:"id"`
	OrgId       uuid.UUID `json:"org_id"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	Version     int       `json:"version"`
	Email       string    `json:"email"`
	Users       int       `json:"users"`
	Agents      int       `json:"agents"`
	XSystemId   XSystemId `json:"x_system_id"`
	XSubId      string    `json:"x_subscription_id"`
	XCustomerId string    `json:"x_customer_id"`
}

func NewSubscription(orgId uuid.UUID, email string, users, agents int, systemId XSystemId, subId, customerId string) Subscription {
	now := time.Now().UTC()
	return Subscription{
		Id:          uuid.NewV1(),
		OrgId:       orgId,
		Created:     now,
		Updated:     now,
		Email:       email,
		Users:       users,
		Agents:      agents,
		XSystemId:   systemId,
		XSubId:      subId,
		XCustomerId: customerId,
	}
}

func (a Subscription) Update(fns ...func(*Subscription)) (ret Subscription) {
	ret = a
	for _, fn := range fns {
		fn(&ret)
	}
	ret.Version = a.Version + 1
	ret.Updated = time.Now().UTC()
	return
}

func UpdateEmail(email string) func(*Subscription) {
	return func(s *Subscription) {
		s.Email = email
	}
}

func UpdateUsers(users int) func(*Subscription) {
	return func(s *Subscription) {
		s.Users = users
	}
}

func UpdateAgents(agents int) func(*Subscription) {
	return func(s *Subscription) {
		s.Agents = agents
	}
}
