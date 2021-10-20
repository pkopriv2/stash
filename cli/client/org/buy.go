package org

import (
	"fmt"
	"regexp"

	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/config"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/term"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/sdk/orgs"
	"github.com/cott-io/stash/sdk/session"
	"github.com/leekchan/accounting"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	OrgFormatMsg = "Must begin with a letter and contain only letters, numbers and dashes"
)

var (
	BuyCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "buy",
			Usage: "buy [<org>]",
			Info:  "Purchase an organization",
			Help: `
Purchase an organization.  Powered by Stripe.com.

# Worry Free

You can cancel the process at anytime with Ctrl-C.

Example:

	$ stash org buy org.example.com
`,
			Exec: OrgBuy,
		})
)

func OrgBuy(env tool.Environment, c *cli.Context) (err error) {
	s, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return
	}
	defer s.Close()

	if err = DisplayStart(env); err != nil {
		return
	}

	on := c.Args().Get(0)
	if on != "" {
		switch {
		case on == orgs.Private:
			err = errors.Wrapf(errs.ArgError, "Cannot be named '%v'", orgs.Private)
		case !org.IsOrg(on):
			err = errors.Wrapf(errs.ArgError, OrgFormatMsg)
		default:
			err = orgs.EnsureAvailable(s, on)
		}
	}

	if err != nil || on == "" {
		if err = DisplayOrgPrompt(env, err); err != nil {
			return
		}

		on, err = ReadOrg(env, s)
		if err != nil || on == "" {
			err = errs.Or(err, errors.Wrapf(errs.ArgError, "No org"))
			return
		}
	}

	users, err := ReadUsers(env, 5)
	if err != nil {
		return
	}

	email, err := ReadEmail(env, "")
	if err != nil {
		return
	}

	if err = DisplaySummary(env, on, email, users); err != nil {
		return
	}

	if err = Confirm(env, "Ok?", true); err != nil {
		return
	}

	if err = DisplayCheckout(env, on); err != nil {
		return
	}

	cc, err := ReadCreditCard(env)
	if err != nil {
		return
	}

	if err = DisplayProcess(env, on); err != nil {
		return
	}

	if err = Confirm(env, "Would you like to checkout?", true); err != nil {
		return
	}

	err = tool.Step(env,
		fmt.Sprintf("\nPurchasing your org [%v]", on), func() (err error) {
			org, err := orgs.Purchase(s, on,
				org.WithEmail(email),
				org.WithUsers(users),
				org.WithCard(cc))
			if err != nil {
				return
			}

			env.Config["stash.session.org"] = org.Id.String()
			err = config.WriteConfig(env.Config, tool.DefaultConfigFile, 0755)
			return
		})
	if err != nil {
		return
	}

	return tool.DisplayStdOut(env, buyDoneTemplate, tool.WithData(struct {
		Org string
	}{
		on,
	}))
}

func NotPrivate(str string) bool {
	return str != orgs.Private
}

const (
	InfoUrl = "https://www.chainoftrust.io/pricing"
)

func IsAvailable(conn session.Session) term.Check {
	return func(cur string) error {
		return orgs.EnsureAvailable(conn, cur)
	}
}

func NewOrgPrompt(env tool.Environment, conn session.Session) term.Prompt {
	return term.NewPrompt(
		"Org Name",
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.AllOk(
				term.IsMatch(NotPrivate, "Orgs cannot be named private"),
				term.IsMatch(org.IsOrg, OrgFormatMsg),
				IsAvailable(conn),
			)))
}

// ** Purchase Prompts ** //

func NewQuantityPrompt(env tool.Environment, prmpt string, def int) term.Prompt {
	return term.NewPrompt(
		prmpt,
		term.WithDefault(fmt.Sprintf("%v", def)),
		term.WithAutoRetry(),
		term.WithAutoInfo(
			term.StaticInfo(fmt.Sprintf("Please see our page: %v", InfoUrl))),
		term.WithAutoCheck(
			term.InRange(0, 100000)))
}

// ** Purchase Prompts ** //
func NewEmailPrompt(env tool.Environment, def string) term.Prompt {
	return term.NewPrompt(
		"Invoice Email",
		term.WithDefault(def),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.IsMatch(auth.IsEmail, "Must be a valid email")))
}

func NewCardNamePrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		fmt.Sprintf("%-18v", "Name On Card"),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.AllOk(
				term.NotShorterThan(4),
				term.NotLongerThan(32))))
}

func NewCardNumberPrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		fmt.Sprintf("%-18v", "Card Number"),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.IsMatch(regexp.
				MustCompile("^[0-9]{16}$").
				MatchString, "xxxxxxxxxxxxxxxx (16-digit number)")))
}

func NewCardExpPrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		fmt.Sprintf("%-18v", "Expiration Month"),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.IsMatch(regexp.
				MustCompile("^[0-9]{2}$").
				MatchString, "mm (2-digit month)")))
}

func NewCardYearPrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		fmt.Sprintf("%-18v", "Expiration Year"),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.IsMatch(regexp.
				MustCompile("^[0-9]{4}$").
				MatchString, "yyyy (4-digit year)")))
}

func NewCardCVCPrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		fmt.Sprintf("%-18v", "Security Code"),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.IsMatch(regexp.
				MustCompile("^[0-9]{3,4}$").
				MatchString, "xxx[x] (3 or 4-digit CVV code)")))
}

func NewCardZipPrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		fmt.Sprintf("%-18v", "ZipCode"),
		term.WithAutoRetry(),
		term.WithAutoCheck(
			term.IsMatch(regexp.
				MustCompile("^[0-9]{5}$").
				MatchString, "xxxxx (5-digit zip code)")))
}

func NewConfirmationPrompt(env tool.Environment, msg string, def bool) term.Prompt {
	init := "yes"
	if !def {
		init = "no"
	}

	return term.NewPrompt(
		msg,
		term.WithDefault(init),
		term.WithAutoCheck(
			term.In("yes", "no")),
		term.WithAutoComplete(
			term.PrefixComplete("yes", "no")))
}

func ReadOrg(env tool.Environment, conn session.Session) (ret string, err error) {
	err = term.ReadPrompt(NewOrgPrompt(env, conn), env.Terminal.IO, term.SetPointer(&ret))
	return
}

func Confirm(env tool.Environment, msg string, def bool) (err error) {
	var yesOrNo string
	if err = term.ReadPrompt(NewConfirmationPrompt(env, msg, def), env.Terminal.IO,
		term.SetPointer(&yesOrNo)); err != nil {
		return
	}

	if yesOrNo != "yes" {
		err = errors.Wrapf(errs.CanceledError, "Purchase canceled")
		return
	}
	return
}

func ReadQuantity(env tool.Environment, prompt string, def int) (val int, err error) {
	err = term.ReadPrompt(NewQuantityPrompt(env, prompt, def), env.Terminal.IO, term.SetInt(&val))
	return
}

func ReadEmail(env tool.Environment, def string) (ret string, err error) {
	if err = tool.DisplayStdOut(env, buyEmailTemplate); err != nil {
		return
	}

	err = term.ReadPrompt(NewEmailPrompt(env, def), env.Terminal.IO, term.SetPointer(&ret))
	return
}

func ReadUsers(env tool.Environment, def int) (val int, err error) {
	if err = tool.DisplayStdOut(env, buyUsersTemplate); err != nil {
		return
	}

	val, err = ReadQuantity(env, "Users", def)
	return
}

func ReadCreditCard(env tool.Environment) (ret billing.Card, err error) {
	err = term.ReadPrompts(
		env.Terminal.IO,
		[]term.Prompt{
			NewCardNamePrompt(env),
			NewCardNumberPrompt(env),
			NewCardExpPrompt(env),
			NewCardYearPrompt(env),
			NewCardCVCPrompt(env),
			NewCardZipPrompt(env),
		},
		term.SetString(&ret.Name),
		term.SetString(&ret.Number),
		term.SetString(&ret.Month),
		term.SetString(&ret.Year),
		term.SetString(&ret.CVC),
		term.SetString(&ret.Zip))
	return
}

// ** Templates ** //
var (
	buyStartTemplate = `
{{ "# Let's get started!" | header }}

We'll now go through the easy purchase process.

{{ "# Worry Free" | header }}

{{ "You can cancel the process at anytime with Ctrl-C." | info }}

`

	buyOrgPromptTemplate = `
{{- "# Enter Org" | header}}

Please enter the name of the organization you'd like to purchase.
{{ if .Err }}

    {{ .Mark | mark }} {{ .Err }}

{{ end}}
`

	buySummaryTemplate = `
{{ "# Plan Details" | header }}

Almost there! Take a moment to review your plan.

    * {{ "Organization  " | info }} {{ .Org }}
    * {{ "Email         " | info }} {{ .Email }}
    * {{ "Users         " | info }} {{ printf "%v" .Users | col 6}} @ {{ printf "%v" .UsersPrice | col 8 }}/User/Month
    -
    * {{ "Total         " | info }} {{.Total}}/Month

`

	buyUsersTemplate = `
{{ "# Reserve User Seats" | header }}

Please select the number of user seats you'd like to reserve.  Seats will
be billed regardless of whether they are occupied.

`

	buyEmailTemplate = `
{{ "# Invoice Email" | header }}

Please specify your invoicing email.

`

	buyCheckoutTemplate = `
{{ "# Payment Options" | header }}

    * {{ "Credit Card " | info }} Powered By Stripe
    * {{ "Other       " | info }} Please email support@cott.io for details

`

	buyUpdateTemplate = `
{{ "# Update Details" | header }}

All changes to subscriptions result in a prorated charge
for the current billing period that will be applied on the
next invoice!

`

	buyUpdateCardTemplate = `
{{ "# Update Your Payment?" | header }}

Would you like to update your payment info?

`

	buyProcessTemplate = `
{{ "# Checkout" | header }}

We will now process your payment.   Don't forget you can cancel your
trial at anytime.

`

	buyDoneTemplate = `
{{ "# Next Steps" | header }}

Get started using your organization!

{{ "# Add Some Members" | header }}

    $ stash org add buddy@example.com --role Owner

{{ "# Cancel Your Subscription" | header }}

    $ stash org cancel

{{ "# Explore Stash" | header }}

    * https://stash.cott.io/docs/

{{ "Congratulations!  You have successfully purchased your org!" | info }}

`
)

func DisplayOrgPrompt(env tool.Environment, err error) error {
	var msg string
	if err != nil {
		msg = err.Error()
	}

	return tool.DisplayStdOut(env, buyOrgPromptTemplate, tool.WithData(struct {
		Mark string
		Err  string
	}{
		tool.ErrorMark,
		msg,
	}))
}

func DisplayStart(env tool.Environment) error {
	return tool.DisplayStdOut(env, buyStartTemplate)
}

func DisplayCheckout(env tool.Environment, on string) (err error) {
	return tool.DisplayStdOut(env, buyCheckoutTemplate, tool.WithData(struct {
		Org string
	}{
		on,
	}))
}

func DisplayProcess(env tool.Environment, on string) (err error) {
	return tool.DisplayStdOut(env, buyProcessTemplate, tool.WithData(struct {
		Org string
	}{
		on,
	}))
}

func DisplayUpdateCard(env tool.Environment) (err error) {
	return tool.DisplayStdOut(env, buyUpdateCardTemplate)
}

func DisplayUpdateNotice(env tool.Environment) (err error) {
	return tool.DisplayStdOut(env, buyUpdateTemplate)
}

func DisplaySummary(env tool.Environment, on, email string, users int) (err error) {
	total := users * 100

	ac := accounting.Accounting{Symbol: "$", Precision: 2}
	return tool.DisplayStdOut(env, buySummaryTemplate, tool.WithData(struct {
		Org        string
		Email      string
		Users      int
		UsersPrice string
		Total      string
	}{
		on,
		email,
		users,
		ac.FormatMoney(float64(100) / float64(100)),
		ac.FormatMoney(float64(total) / float64(100)),
	}))
}

var (
	MembersFlag = cli.IntFlag{
		Name:  "members",
		Usage: "The maximum number of active members in the organization",
	}
)
