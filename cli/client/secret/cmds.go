package secret

import "github.com/cott-io/stash/lang/tool"

var (
	Commands = tool.NewGroup(
		tool.GroupDef{
			Name: "secret",
			Info: "Manage your organization's secrets",
		},
		EditCommand,
		ViewCommand,
		ExecCommand,
		CpCommand,
		LsCommand,
		MvCommand,
		RmCommand,
		ACLTools,
	)
)
