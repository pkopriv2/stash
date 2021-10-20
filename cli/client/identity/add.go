package identity

import (
	"fmt"

	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	AddCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "add",
			Usage: "add <identity>",
			Info:  "Adds a key, email, or phone",
			Help: `
Adds a public identity to your account.  If the identity
is verifiable, it must be verified subsequent to adding.

Examples:

Add a signing key to your acccount:

	$ stash identity add key.pem

Add an email to your account (require's verification):

	$ stash identity add user@example.com
	$ stash identity verify user@example.com

Add a phone number to your account (require's verification):

	$ stash identity add 913-555-5555
	$ stash identity verify 913-555-5555
`,
			Exec: IdentityAdd,
		})
)

// ** RAW COMMANDS ** //

func IdentityAdd(env tool.Environment, c *cli.Context) (err error) {
	if len(c.Args()) != 1 {
		err = errors.Wrapf(errs.ArgError, "Must provide an identity")
		return
	}

	id, err := auth.ParseFriendlyIdentity(c.Args().Get(0))
	if err != nil {
		return
	}

	session, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return err
	}
	defer session.Close()

	switch id.Proto {
	default:
		err = errors.Wrapf(auth.ErrBadArgs, "Unsupported identity type [%v]", id)
		return
	case auth.Pem:
		var signer crypto.PrivateKey

		signer, err = client.ReadPrivateKey(env, id.Value())
		if err != nil {
			return
		}

		if err = accounts.AddSigner(session, signer); err != nil {
			return
		}
	case auth.Phone:
		if err = accounts.AddIdentity(session, id, auth.WithPrivacy()); err != nil {
			return
		}
	case auth.User, auth.UUID, auth.Email:
		if err = accounts.AddIdentity(session, id); err != nil {
			return
		}
	}

	fmt.Fprintf(env.Terminal.IO.StdOut(), "\nSuccessfully added identity [%v]\n", id)
	return
}
