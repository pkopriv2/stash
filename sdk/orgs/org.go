package orgs

import (
	"strings"

	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	Private = "private"
)

func CollectIds(orgs []org.Org) (ret []uuid.UUID) {
	ret = make([]uuid.UUID, 0, len(orgs))
	for _, o := range orgs {
		ret = append(ret, o.Id)
	}
	return
}

func EnsureAvailable(s session.Session, name string) (err error) {
	if strings.ToLower(strings.Trim(name, " ")) == Private {
		err = errs.Or(err, errors.Wrapf(errs.ArgError, "Private orgs not available"))
		return
	}

	orgn, _, err := LoadByName(s, name)
	if err != nil || orgn.Enabled {
		err = errs.Or(err, errors.Wrapf(org.ErrOrgExists, "Org already claimed [%v]", name))
	}
	return
}

func LoadByName(s session.Session, name string) (ret org.Org, found bool, err error) {
	if strings.ToLower(strings.Trim(name, " ")) == Private {
		name = s.AccountId().String()
	}

	token, err := s.FetchToken()
	if err != nil {
		return
	}

	ret, found, err = s.Options().Orgs().LoadOrgByName(token, name)
	return
}

func LoadById(s session.Session, id uuid.UUID) (ret org.Org, found bool, err error) {
	token, err := s.FetchToken(auth.WithOrgId(id))
	if err != nil {
		return
	}

	ret, found, err = s.Options().Orgs().LoadOrgById(token, id)
	return
}

func ListByIds(s session.Session, ids []uuid.UUID) (ret []org.Org, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}

	ret, err = s.Options().Orgs().ListOrgsByIds(token, ids)
	return
}

func Cancel(s session.Session, id uuid.UUID) (err error) {
	token, err := s.FetchToken(auth.WithOrgId(id))
	if err != nil {
		return
	}

	err = s.Options().Orgs().DeleteSubscription(token, id)
	return
}

// Purchases an org.  The provided org will be the public identity of the
// group associated with the org.  A side-effect of org creation
// is that the session owner is automatically added as a member at the Owner level.
// Owners are free to invite members at any level.
func Purchase(s session.Session, name string, opts ...org.PurchaseOption) (ret org.Org, err error) {
	token, err := s.FetchToken()
	if err != nil {
		return
	}

	billingKey, err := s.Options().Orgs().LoadBillingKey(token)
	if err != nil {
		err = errors.Wrapf(err, "Unable to load server info")
		return
	}

	// If no billing key is available, then we're in a self-hosted scenario.
	purchase := org.BuildPurchase(opts...)
	if billingKey != "" {
		if purchase.Payment == nil || purchase.Payment.Card == nil {
			err = errors.Wrapf(billing.ErrPayment, "Missing required credit card")
			return
		}

		token, err := billing.NewStripeClient(billingKey).NewPaymentToken(*purchase.Payment)
		if err != nil {
			return ret, err
		}

		opts = append(opts, org.WithToken(token))
	} else {
		opts = append(opts, org.WithToken(""))
	}

	ret, err = s.Options().Orgs().Purchase(token, name, org.BuildPurchase(opts...))
	return
}
