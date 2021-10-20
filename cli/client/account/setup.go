package account

import (
	"fmt"

	"github.com/cott-io/stash/lang/config"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/term"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	DefaultKeyFile = "~/.stash/key.pem"
)

func IsEmailAvailable(s session.Session) term.Check {
	return func(cur string) error {
		return accounts.RequireIdentityUnverified(s, auth.ByEmail(cur))
	}
}

func NewKeyFilePrompt() term.Prompt {
	return term.NewPrompt(
		"Private Key",
		term.WithAutoRetry(),
		term.WithDefault(DefaultKeyFile))
}

func NewEmailPrompt(env tool.Environment, conn session.Session) term.Prompt {
	return term.NewPrompt(
		"Your Email",
		term.WithAutoRetry(),
		term.WithAutoInfo(
			term.StaticInfo("Optional")),
		term.WithAutoCheck(
			term.AllOk(
				term.IsMatch(IsEmailOrEmpty, "Must be a valid email address or empty!"),
				IsEmailAvailable(conn),
			)))
}

func IsEmailOrEmpty(str string) bool {
	return str == "" || auth.IsEmail(str)
}

func NewVerifyPrompt(env tool.Environment) term.Prompt {
	return term.NewPrompt(
		"Verification Code",
		term.WithAutoRetry(),
		term.WithAutoCheck(term.NotEmpty()))
}

// ** Templates ** //

var (
	setupIntroTemplate = `
{{ "# Getting Started" | header }}

We'll now go through the account registration process.  It will do the
following:

    {{ "*" | item }} Generate and register your account's private key
    {{ "*" | item }} Generate and register your account's recovery passphrase
    {{ "*" | item }} Register your email (*optional*)

`

	saveKeyTemplate = `
{{ "# Save Your Private Key" | header }}

We'll need to store a private key on your machine.  This will not leave
your device.

`

	setupEmailTemplate = `
{{ "# Register Your Email?" | header }}

Leave empty to opt out.

`

	setupVerifyEmailTemplate = `
{{ "# Verify Your Email" | header }}

You will receive a message shortly with a verification code.

`
	setupBasicSuccessTemplate = `
{{ "# Basic Setup Done" | header }}

Congratulations! You have registered your account.

`

	setupRecoveryTemplate = `
{{ "# Save Your Recovery Key" | header }}

This recovery phrase may be used to recover your account.  Please
write down and store your recovery key in a safe location.

    {{ .Recovery | item }}
`

	setupErrorTemplate = `
{{ "# Error!" | header }}

    {{.Error | mark }} {{.Msg}}

`

	setupDoneTemplate = `
{{ "# That's It" | header }}

You're account's ready to go! Next steps:

    {{ "*" | item }} Purchase an organization.

        $ stash org buy <org>

`
)

func DisplaySetupIntro(env tool.Environment) (err error) {
	err = tool.DisplayStdOut(env, setupIntroTemplate)
	return
}

func DisplaySetupError(env tool.Environment, err error) error {
	return tool.DisplayStdOut(env, setupErrorTemplate, tool.WithData(struct {
		Error string
		Msg   string
	}{
		tool.ErrorMark,
		err.Error(),
	}))
}

func DisplaySetupDone(env tool.Environment) error {
	return tool.DisplayStdOut(env, setupDoneTemplate)
}

func PromptKeyFile(env tool.Environment) (file string, err error) {
	if err = tool.DisplayStdOut(env, saveKeyTemplate); err != nil {
		return
	}

	err = term.ReadPrompt(NewKeyFilePrompt(), env.Terminal.IO, term.SetString(&file))
	return
}

func PromptEmail(env tool.Environment, conn session.Session) (email string, err error) {
	if err = tool.DisplayStdOut(env, setupEmailTemplate); err != nil {
		return
	}

	err = term.ReadPrompt(NewEmailPrompt(env, conn), env.Terminal.IO, term.SetPointer(&email))
	return
}

func PromptVerify(env tool.Environment) (code string, err error) {
	if err = tool.DisplayStdOut(env, setupVerifyEmailTemplate); err != nil {
		return
	}

	err = term.ReadPrompt(NewVerifyPrompt(env), env.Terminal.IO, term.SetPointer(&code))
	return
}

func DisplayBasicSetupDone(env tool.Environment) error {
	return tool.DisplayStdOut(env, setupBasicSuccessTemplate)
}

func DisplayRecoveryPhrase(env tool.Environment, pass string) error {
	return tool.DisplayStdOut(env, setupRecoveryTemplate, tool.WithData(struct {
		Recovery string
	}{
		pass,
	}))
}

func WriteConfig(env tool.Environment) error {
	return config.WriteConfig(env.Config, tool.DefaultConfigFile, 0755)
}

// TODO: internationalize
var (
	StrengthFlag = tool.StringFlag{
		Name:    "strength",
		Usage:   "The account strength [Minimal, Moderate, Strong, Maximum]",
		Default: "Moderate",
	}

	SetupCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "setup",
			Usage: "setup",
			Info:  "Configure and register your client",
			Help: `
Setup a new account with the Stash services.

`,
			Flags: tool.NewFlags(StrengthFlag),
			Exec:  AccountSetup,
		})
)

// ** RAW COMMANDS ** //

func AccountSetup(env tool.Environment, cli *cli.Context) (err error) {
	if err = DisplaySetupIntro(env); err != nil {
		return
	}

	if err = tool.Confirm(env, "Continue?"); err != nil {
		return
	}

	defer func() {
		if err != nil {
			DisplaySetupError(env, err)
		} else {
			DisplaySetupDone(env)
		}
	}()

	strength, err := crypto.ParseStrength(cli.String(StrengthFlag.Name))
	if err != nil {
		return
	}

	key, err := strength.GenKey(crypto.Rand, crypto.RSA)
	if err != nil {
		return
	}
	defer crypto.Destroy(key)

	file, err := PromptKeyFile(env)
	if err != nil {
		return
	}

	err = tool.Step(env,
		fmt.Sprintf("\n%-50v", "* Saving your private key:"), func() (err error) {
			return crypto.WritePrivateKeyFile(key, file, crypto.PKCS1Encoder)
		})
	if err != nil {
		return
	}

	env.Config["stash.session.strength"] = strength.String()
	env.Config["stash.session.key"] = file
	err = tool.Step(env,
		fmt.Sprintf("%-50v", "* Saving your configuration:"), func() (err error) {
			return config.WriteConfig(env.Config, tool.DefaultConfigFile, 0755)
		})
	if err != nil {
		return
	}

	recovery, err := strength.GenPass(crypto.Rand)
	if err != nil {
		return
	}
	defer crypto.Bytes([]byte(recovery)).Destroy()

	id, login :=
		auth.ByKey(key.Public()),
		auth.WithSignature(key, strength)

	err = tool.Step(env,
		fmt.Sprintf("%-50v", "* Registering your account:"), func() (err error) {
			return session.Register(env.Context, id, login, session.WithConfig(env.Config))
		})
	if err != nil {
		return
	}

	conn, err := session.Authenticate(env.Context, id, login, session.WithConfig(env.Config))
	if err != nil {
		return
	}

	err = tool.Step(env,
		fmt.Sprintf("%-50v", "* Registering your recovery phrase:"), func() (err error) {
			return accounts.AddLogin(conn, auth.WithPassword([]byte(recovery)))
		})
	if err != nil {
		return
	}

	defer func() {
		if err == nil {
			DisplayRecoveryPhrase(env, recovery)
		}
	}()

	email, err := PromptEmail(env, conn)
	if err != nil || email == "" {
		return
	}

	emailId := auth.ByEmail(email)
	if err = accounts.AddIdentity(conn, emailId); err != nil {
		return
	}

	for {
		code, err := PromptVerify(env)
		if err != nil {
			return err
		}

		err = accounts.IdentityVerify(conn, emailId, auth.WithPassword([]byte(code)))
		if !errs.Is(err, auth.ErrAuthAttempt) {
			return err
		}

		err = errors.Wrapf(auth.ErrAuthAttempt, "Invalid code")
		term.DisplayColoredError(env.Terminal.IO, err)
	}
	return
}
