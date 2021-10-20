package group

import "github.com/cott-io/stash/lang/tool"

var (
	Commands = tool.NewGroup(
		tool.GroupDef{
			Name: "group",
			Info: "Manage your organization's groups",
		},
		CreateCommand,
		LsCommand,
		RmCommand,
		ACLTools,
	)
)
