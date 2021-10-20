package core

import (
	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/env"
	"github.com/cott-io/stash/lang/mail"
	"github.com/cott-io/stash/lang/sms"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/libs/secret"
)

const (
	Signer     = "deps.signer"
	Biller     = "deps.billing"
	BillingKey = "deps.billing.key"
	Mailer     = "deps.mail"
	Texter     = "deps.sms"
	Accounts   = "deps.storage.accounts"
	Orgs       = "deps.storage.orgs"
	Policies   = "deps.storage.policies"
	Secrets    = "deps.storage.secrets"
)

func AssignBillingKey(e env.Environment) (ret string) {
	e.Assign(BillingKey, &ret)
	return
}

func AssignBiller(e env.Environment) (ret billing.Client) {
	e.Assign(Biller, &ret)
	return
}

func AssignMailer(e env.Environment) (ret mail.Client) {
	e.Assign(Mailer, &ret)
	return
}

func AssignTexter(e env.Environment) (ret sms.Client) {
	e.Assign(Texter, &ret)
	return
}

func AssignSigner(e env.Environment) (ret crypto.Signer) {
	e.Assign(Signer, &ret)
	return
}

func AssignAccounts(e env.Environment) (ret account.Storage) {
	e.Assign(Accounts, &ret)
	return
}

func AssignOrgs(e env.Environment) (ret org.Storage) {
	e.Assign(Orgs, &ret)
	return
}

func AssignPolicies(e env.Environment) (ret policy.Storage) {
	e.Assign(Policies, &ret)
	return
}

func AssignSecrets(e env.Environment) (ret secret.Storage) {
	e.Assign(Secrets, &ret)
	return
}
