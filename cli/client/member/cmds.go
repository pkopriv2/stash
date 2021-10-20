package member

import "github.com/cott-io/stash/lang/tool"

var (
	Commands = tool.NewGroup(
		tool.GroupDef{
			Name: "member",
			Info: "Manage your organization's members",
		},
		LsCommand,
		AddCommand,
		RmCommand,
	)
)
