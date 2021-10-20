package identity

import (
	"fmt"

	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	RmCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "rm",
			Usage: "rm <identity>",
			Info:  "Removes an identity",
			Help: `
Remove a trusted identity from your account.  This identity
will no longer be able to authenticate.  Outstanding tokens
are still accepted.

Examples:

Remove a signing key from your acccount:

	$ stash identity rm key.pem

Remove an email from your account:

	$ stash identity rm user@example.com
`,
			Flags: client.AuthFlags,
			Exec:  IdentityRm,
		})
)

// ** RAW COMMANDS ** //

func IdentityRm(env tool.Environment, c *cli.Context) (err error) {
	if len(c.Args()) != 1 {
		err = errors.Wrapf(errs.ArgError, "Must provide an identity")
		return
	}

	id, err := client.LoadIdentity(env, c.Args().Get(0))
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
	case auth.Key:
		if err = accounts.DeleteSignerById(session, id.Value()); err != nil {
			return
		}
	case auth.User, auth.UUID, auth.Email, auth.Phone:
		if err = accounts.DeleteIdentity(session, id); err != nil {
			return
		}
	}

	fmt.Fprintf(env.Terminal.IO.StdOut(), "\nSuccessfully removed identity [%v]\n", id)
	return
}
