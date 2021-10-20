package identity

import (
	"github.com/cott-io/stash/lang/tool"
)

var (
	Commands = tool.NewGroup(
		tool.GroupDef{
			Name: "identity",
			Info: "Manage your account",
		},
		AddCommand,
		VerifyCommand,
		LsCommand,
		RmCommand,
	)
)
