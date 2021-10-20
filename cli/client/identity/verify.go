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
	VerifyCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "verify",
			Usage: "verify <identity> [<code>]",
			Info:  "Verify an identity",
			Help: `
Verifies an account identity.  A code may supplied as the second
argument.  If it is not supplied, you will be prompted.

Identities are the public, physical binding to your account.  They
are used as a means to establish a verifiable trust chain all the way
from the point of login to any piece of data affected by the account.

Examples:

Verify an email:

	$ stash identity verify me@example.com 12345

Verify a phone:

	$ stash identity verify 913-555-5555 12345
`,
			Exec: IdentityVerify,
		})
)

// ** RAW COMMANDS ** //

func IdentityVerify(env tool.Environment, c *cli.Context) (err error) {
	if len(c.Args()) < 1 {
		err = errors.Wrapf(errs.ArgError, "Must provide an identity")
		return
	}

	s, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return
	}
	defer s.Close()

	id, err := client.LoadIdentity(env, c.Args().Get(0))
	if err != nil {
		return
	}

	var login auth.Login
	if code := c.Args().Get(1); code != "" {
		login = auth.WithPassword([]byte(code))
	} else {
		login = auth.WithTerminalPassword(env.Terminal, client.VerifyPrompt)
	}

	if err = accounts.IdentityVerify(s, id, login); err != nil {
		return
	}

	fmt.Fprintf(env.Terminal.IO.StdOut(), "\nSuccessfully verified account [%v]\n", id)
	return
}
