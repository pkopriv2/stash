package group

import (
	"github.com/cott-io/stash/cli/client"
	"github.com/cott-io/stash/lang/tool"
	"github.com/urfave/cli"
)

var (
	ACLTools = tool.NewGroup(
		tool.GroupDef{
			Name:  "acl",
			Usage: "acl <command> [args]*",
			Info:  "Manage group access controls",
		},
		GrantCommand,
		RevokeCommand,
		RosterCommand,
	)

	GrantCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "grant",
			Usage: "grant <secret> <member> [<action>]*",
			Info:  "Grant actions to a member",
			Help:  ``,
			Exec: func(env tool.Environment, c *cli.Context) (err error) {
				return client.GrantPolicyMember(env, c, "group")
			},
		})

	RevokeCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "revoke",
			Usage: "revoke <secret> <member> [<action>]*",
			Info:  "Revoke actions from a member",
			Help: `
Revokes privileges from a user.  If no actions are given,
the membership is deleted.
`,
			Exec: func(env tool.Environment, c *cli.Context) (err error) {
				return client.RevokePolicyMember(env, c, "group")
			},
		})

	RosterCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "ls",
			Usage: "ls <secret>",
			Info:  "List members and their actions",
			Help:  ``,
			Exec: func(env tool.Environment, c *cli.Context) (err error) {
				return client.ListPolicyMembers(env, c, "group")
			},
		})
)
