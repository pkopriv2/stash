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

// ** Templates ** //

var (
	recoverIntroTemplate = `
{{ "# Account Recovery" | header }}

Please have your recovery passphrase ready.

`
	recoverDoneTemplate = `
{{ "# Account Recovered!" | header }}

You're account has been successfully recovered!

`
)

// ** Prompts ** //

func newRecoverPrompt() term.Prompt {
	return term.NewPrompt(
		"Your recovery passphrase",
		term.WithAutoRetry(),
		term.WithAutoCheck(term.NotEmpty()))
}

func promptRecoveryPass(env tool.Environment) (code []byte, err error) {
	err = term.ReadPrompt(newRecoverPrompt(), env.Terminal.IO, term.SetBytes(&code))
	return
}

var (
	RecoverCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "recover",
			Usage: "recover <identity>",
			Info:  "Recover an account",
			Help:  `Account recovery`,
			Flags: tool.NewFlags(StrengthFlag),
			Exec: func(env tool.Environment, cli *cli.Context) (err error) {
				if len(cli.Args()) != 1 {
					err = errors.Wrapf(errs.ArgError, "Must provide an identity to recover")
					return
				}

				id, err := auth.ParseFriendlyIdentity(cli.Args().Get(0))
				if err != nil {
					return
				}

				strength, err := crypto.ParseStrength(cli.String(StrengthFlag.Name))
				if err != nil {
					return
				}

				if err = tool.DisplayStdOut(env, recoverIntroTemplate); err != nil {
					return
				}
				defer func() {
					if err == nil {
						tool.DisplayStdOut(env, recoverDoneTemplate)
					}
				}()

				pass, err := promptRecoveryPass(env)
				if err != nil {
					return
				}
				defer crypto.Destroy(crypto.Bytes(pass))

				key, err := strength.GenKey(crypto.Rand, crypto.RSA)
				if err != nil {
					return
				}
				defer crypto.Destroy(key)

				file, err := PromptKeyFile(env)
				if err != nil {
					return
				}

				err = tool.Step(env, fmt.Sprintf("\n%-50v", "* Saving your private key:"), func() (err error) {
					return crypto.WritePrivateKeyFile(key, file, crypto.PKCS1Encoder)
				})
				if err != nil {
					return
				}

				env.Config["stash.session.key"] = file
				err = tool.Step(env, fmt.Sprintf("%-50v", "* Saving your configuration:"), func() (err error) {
					return config.WriteConfig(env.Config, tool.DefaultConfigFile, 0755)
				})
				if err != nil {
					return
				}

				s, err := session.Authenticate(env.Context, id, auth.WithPassword(pass), session.WithConfig(env.Config))
				if err != nil {
					err = errors.Wrapf(auth.ErrUnauthorized, "Unable to login")
					return
				}

				err = tool.Step(env, fmt.Sprintf("%-50v", "* Recovering account:"),
					func() (err error) {
						return accounts.AddSigner(s, key)
					})
				if err != nil {
					return
				}
				return
			},
		})
)
