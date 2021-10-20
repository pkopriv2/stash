package billing

import (
	"fmt"
	"time"

	"github.com/cott-io/stash/lang/errs"
	"github.com/pkg/errors"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/client"
)

const (
	stripeUsersPlan  = "plan_DSvQHtBTmCt9MV"
	stripeAgentsPlan = "plan_DXQeYEnCAStN4r"
)

// Turn off stripe logging
func init() {
	stripe.LogLevel = 0
}

type StripeClient struct {
	raw *client.API
}

func NewStripeClient(key string) Client {
	return &StripeClient{client.New(key, nil)}
}

func (s *StripeClient) NewPaymentToken(p Payment) (ret string, err error) {
	tok, err := s.raw.Tokens.New(&stripe.TokenParams{
		Card: &stripe.CardParams{
			Name:       &p.Card.Name,
			Number:     &p.Card.Number,
			CVC:        &p.Card.CVC,
			ExpMonth:   &p.Card.Month,
			ExpYear:    &p.Card.Year,
			AddressZip: &p.Card.Zip,
		},
	})
	if err != nil {
		return
	}

	ret = tok.ID
	return
}

func (s *StripeClient) NewCustomer(email, token string) (ret Customer, err error) {
	raw, err := s.raw.Customers.New(&stripe.CustomerParams{
		Email: &email,
		Source: &stripe.SourceParams{
			Token: &token,
		},
	})
	if err != nil {
		err = newBillingError(err)
		return
	}

	var payment Payment
	if len(raw.Sources.Data) > 0 {
		src := raw.Sources.Data[0]
		switch src.Type {
		case stripe.PaymentSourceTypeCard:
			payment.Card = &Card{
				Name:  src.Card.Name,
				Month: fmt.Sprintf("%v", src.Card.ExpMonth),
				Year:  fmt.Sprintf("%v", src.Card.ExpYear),
				Brand: string(src.Card.Brand),
				Last4: src.Card.Last4,
			}
		}
	}

	ret = Customer{raw.ID, raw.Email, payment}
	return
}

func (s *StripeClient) UpdateCustomer(c Customer) (err error) {
	var email *string
	if c.Email != "" {
		email = &c.Email
	}

	var source *stripe.SourceParams
	if c.Payment.Token != nil {
		source = &stripe.SourceParams{
			Token: c.Payment.Token,
		}
	}

	_, err = s.raw.Customers.Update(c.Id, &stripe.CustomerParams{
		Email:  email,
		Source: source,
	})
	err = newBillingError(err)
	return
}

func (s *StripeClient) GetCustomer(id string) (ret Customer, ok bool, err error) {
	raw, err := s.raw.Customers.Get(id, &stripe.CustomerParams{})
	if err != nil || raw == nil {
		err = newBillingError(err)
		return
	}

	var payment Payment
	if len(raw.Sources.Data) > 0 {
		src := raw.Sources.Data[0]
		switch src.Type {
		case stripe.PaymentSourceTypeCard:
			payment.Card = &Card{
				Name:  src.Card.Name,
				Month: fmt.Sprintf("%v", src.Card.ExpMonth),
				Year:  fmt.Sprintf("%v", src.Card.ExpYear),
				Brand: string(src.Card.Brand),
				Last4: src.Card.Last4,
			}
		}
	}

	ok, ret = true, Customer{raw.ID, raw.Email, payment}
	return
}

func (s *StripeClient) NewSubscription(customerId string, items []Item) (id string, err error) {
	params, err := toSubscriptionParams(items)
	if err != nil {
		return
	}

	raw, err := s.raw.Subscriptions.New(&stripe.SubscriptionParams{
		Customer: &customerId,
		Items:    params,
	})
	if err != nil {
		err = newBillingError(err)
		return
	}
	id = raw.ID
	return
}

func (s *StripeClient) CancelSubscription(subId string) (err error) {
	_, err = s.raw.Subscriptions.Cancel(subId, nil)
	err = newBillingError(err)
	return
}

func (s *StripeClient) UpdateSubscription(subId string, items []Item) (err error) {

	sub, err := s.raw.Subscriptions.Get(subId, nil)
	if err != nil {
		return
	}

	params := make([]*stripe.SubscriptionItemsParams, 0, len(items))
	for _, s := range sub.Items.Data {
		for _, i := range items {
			var planId string
			switch i.Plan {
			default:
				err = errors.Wrapf(errs.ArgError, "Unknown item [%v]", i.Plan)
				return
			case Users:
				planId = stripeUsersPlan
			case Agents:
				planId = stripeAgentsPlan
			}

			if s.Plan.ID != planId {
				continue
			}

			n := i.Quantity
			params = append(params, &stripe.SubscriptionItemsParams{
				ID:       &s.ID,
				Quantity: &n,
			})

		}
	}

	_, err = s.raw.Subscriptions.Update(subId, &stripe.SubscriptionParams{
		Items: params,
	})
	err = newBillingError(err)
	return
}

func (s *StripeClient) NextInvoice(customerId, subId string) (ret Invoice, err error) {
	inv, err := s.raw.Invoices.GetNext(&stripe.InvoiceParams{
		Customer:     &customerId,
		Subscription: &subId,
	})
	if err != nil {
		return
	}
	ret = fromStripeInvoice(inv)
	return
}

func (s *StripeClient) ListInvoices(subId string, start *string, max int64) (ret []Invoice, err error) {
	iter := s.raw.Invoices.List(&stripe.InvoiceListParams{
		Subscription: &subId,
		ListParams: stripe.ListParams{
			StartingAfter: start,
			Limit:         &max,
		},
	})

	if err = iter.Err(); err != nil {
		err = newBillingError(err)
		return
	}

	ret = make([]Invoice, 0, iter.Meta().TotalCount)
	for iter.Next() {
		if err = iter.Err(); err != nil {
			err = newBillingError(err)
			return
		}

		ret = append(ret, fromStripeInvoice(iter.Invoice()))
	}
	return
}

func fromStripeInvoice(raw *stripe.Invoice) (ret Invoice) {
	ret = Invoice{
		Id:         raw.ID,
		CustomerId: raw.Customer.ID,
		SubId:      raw.Subscription.ID,
		//Date:         time.Unix(raw.Date, 0),
		DueDate:      time.Unix(raw.DueDate, 0),
		Desc:         raw.Description,
		Paid:         raw.Paid,
		PeriodStart:  time.Unix(raw.PeriodStart, 0),
		PeriodEnd:    time.Unix(raw.PeriodEnd, 0),
		BalanceStart: raw.StartingBalance,
		BalanceEnd:   raw.EndingBalance,
		Subtotal:     raw.Subtotal,
		Tax:          raw.Tax,
		TaxPercent:   raw.TaxPercent,
		Total:        raw.Total,
	}
	return
}

func newBillingError(raw error) (err error) {
	if raw == nil {
		return
	}

	serr, ok := raw.(*stripe.Error)
	if !ok {
		return raw
	}

	err = errors.Wrapf(ErrPayment, "StripeError(%v, %v): %v", serr.Type, serr.Code, serr.Msg)
	return
}

func toSubscriptionParams(items []Item) (ret []*stripe.SubscriptionItemsParams, err error) {
	ret = make([]*stripe.SubscriptionItemsParams, 0, len(items))
	for _, i := range items {
		tmp := i

		var plan string
		switch tmp.Plan {
		default:
			err = errors.Wrapf(errs.ArgError, "Unknown item [%v]", tmp.Plan)
			return
		case Users:
			plan = stripeUsersPlan
		case Agents:
			plan = stripeAgentsPlan
		}

		ret = append(ret, &stripe.SubscriptionItemsParams{
			Plan:     &plan,
			Quantity: &tmp.Quantity,
		})
	}
	return
}
