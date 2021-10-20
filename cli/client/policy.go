package client

import (
	"fmt"
	"strings"

	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/sdk/policies"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

func GrantPolicyMember(env tool.Environment, c *cli.Context, proto string) (err error) {
	if len(c.Args()) < 2 {
		err = errors.Wrapf(errs.ArgError, "Must provide an item and a member")
		return
	}

	item := c.Args().Get(0)
	if proto != "" {
		if cur := ref.Pointer(item).Protocol(); cur != "" && cur != proto {
			err = errors.Wrapf(errs.ArgError, "Unexpected protocol [%v]. Expected [%v]", cur, proto)
			return
		}

		item = ref.Pointer(item).SetProtocol(proto).Raw()
	}

	// Load the policy item.
	itemRef, err := policies.ParseItemRef(item)
	if err != nil {
		return
	}

	memberRef, err := policies.ParseMemberRef(c.Args().Get(1))
	if err != nil {
		return
	}

	// Determine which actions to grant
	var actions []policy.Action
	if len(c.Args()) > 2 {
		for _, arg := range c.Args()[2:] {
			act, err := itemRef.ParseAction(arg)
			if err != nil {
				return err
			}

			actions = append(actions, act)
		}
	} else {
		actions = itemRef.Type.DefaultActions()
	}

	s, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return
	}
	defer s.Close()

	orgId, err := s.Options().RequireOrgId()
	if err != nil {
		return
	}

	itemPolicyId, err := itemRef.GetPolicyId(s, orgId)
	if err != nil {
		return
	}

	itemLock, err := policies.RequirePolicyLock(s, orgId, itemPolicyId, s.AccountId())
	if err != nil {
		return
	}

	memberId, err := memberRef.GetMemberId(s, orgId)
	if err != nil {
		return
	}

	if err = policies.GrantPolicyMember(s, itemLock, memberRef.Type, memberId, actions...); err != nil {
		return
	}

	_, err = fmt.Fprintf(
		env.Terminal.IO.StdOut(), "\nSuccessfully granted actions %v to member [%v] for [%v]\n", actions, memberRef, itemRef)
	return
}

func RevokePolicyMember(env tool.Environment, c *cli.Context, proto string) (err error) {
	if len(c.Args()) < 2 {
		err = errors.Wrapf(errs.ArgError, "Must provide an item and a member")
		return
	}

	item := c.Args().Get(0)
	if proto != "" {
		if cur := ref.Pointer(item).Protocol(); cur != "" && cur != proto {
			err = errors.Wrapf(errs.ArgError, "Unexpected protocol [%v]. Expected [%v]", cur, proto)
			return
		}

		item = ref.Pointer(item).SetProtocol(proto).Raw()
	}

	itemRef, err := policies.ParseItemRef(item)
	if err != nil {
		return
	}

	memberRef, err := policies.ParseMemberRef(c.Args().Get(1))
	if err != nil {
		return
	}

	// Determine which actions to revoke
	var actions []policy.Action
	if len(c.Args()) > 2 {
		for _, arg := range c.Args()[2:] {
			act, err := itemRef.Type.ParseAction(arg)
			if err != nil {
				return err
			}

			actions = append(actions, act)
		}
	}

	s, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return
	}
	defer s.Close()

	orgId, err := s.Options().RequireOrgId()
	if err != nil {
		return
	}

	itemPolicyId, err := itemRef.GetPolicyId(s, orgId)
	if err != nil {
		return
	}

	itemLock, err := policies.RequirePolicyLock(s, orgId, itemPolicyId, s.AccountId())
	if err != nil {
		return
	}

	members, err := policies.ListPolicyMembers(s, orgId, itemPolicyId, page.Limit(2))
	if err != nil {
		return
	}

	if len(members) <= 1 {
		err = errors.Wrap(policy.ErrEmptyPolicy, "Cannot remove last member")
		return
	}

	memberId, err := memberRef.GetMemberId(s, orgId)
	if err != nil {
		return
	}

	if err = policies.RevokePolicyMember(s, itemLock, memberId, actions...); err != nil {
		return
	}

	_, err = fmt.Fprintf(env.Terminal.IO.StdOut(), "\nSucccessfully revoked %v from [%v] of [%v]\n", actions, memberRef, itemRef)
	return
}

func ListPolicyMembers(env tool.Environment, c *cli.Context, proto string) (err error) {
	if len(c.Args()) < 1 {
		err = errors.Wrapf(errs.ArgError, "Must provide an item")
		return
	}

	item := c.Args().Get(0)
	if proto != "" {
		if cur := ref.Pointer(item).Protocol(); cur != "" && cur != proto {
			err = errors.Wrapf(errs.ArgError, "Unexpected protocol [%v]. Expected [%v]", cur, proto)
			return
		}

		item = ref.Pointer(item).SetProtocol(proto).Raw()
	}

	itemRef, err := policies.ParseItemRef(item)
	if err != nil {
		return
	}

	s, err := session.NewDefaultSession(env.Context, env.Config)
	if err != nil {
		return
	}
	defer s.Close()

	orgId, err := s.Options().RequireOrgId()
	if err != nil {
		return
	}

	policyId, err := itemRef.GetPolicyId(s, orgId)
	if err != nil {
		return
	}

	results, err := policies.ListPolicyMembers(s, orgId, policyId, tool.ParsePageOpts(c)...)
	if err != nil {
		return
	}

	return tool.DisplayStdOut(env, policyRosterTemplate,
		tool.WithFunc("actions", ActionsFormatter),
		tool.WithData(struct {
			Item    policies.ItemRef
			Members []policy.PolicyMemberInfo
		}{
			itemRef,
			policy.SortPolicyMembers(results, policy.FormatSorter),
		}))
}

var (
	policyRosterTemplate = `
Members(Total={{len .Members}}):

      {{ "#/id" | col 64 | header }} {{ "#/enabled actions" | header }}

{{- range .Members}}
    {{"*" | item}} {{ .Format | col 64 }} [{{ .Actions | actions | info }}]
{{- end}}
`
)

//func CheckPolicyMember(env Environment, c *cli.Context, proto string) (err error) {
//if len(c.Args()) < 1 {
//err = errs.ArgError
//return
//}

//item := c.Args().Get(0)
//if proto != "" {
//if cur := enc.Pointer(item).Protocol(); cur != "" && cur != proto {
//err = errors.Wrapf(errs.ArgError, "Unexpected protocol [%v]. Expected [%v]", cur, proto)
//return
//}

//item = enc.Pointer(item).SetProtocol(proto).Raw()
//}

//itemRef, err := policies.ParseItemRef(item)
//if err != nil {
//return
//}

//s, err := SignInByTerminal(env, c)
//if err != nil {
//return err
//}
//defer s.Close()

//orgId, err := LoadOrgId(s, c)
//if err != nil {
//return
//}

//policyId, err := itemRef.GetPolicyId(s, orgId)
//if err != nil {
//return
//}

//memberId := s.AcctId()
//if len(c.Args()) > 1 {
//memberRef, err := policies.ParseMemberRef(c.Args().Get(1))
//if err != nil {
//return err
//}

//memberId, err = memberRef.GetMemberId(s, orgId)
//if err != nil {
//return err
//}
//}

//member, err := policies.RequirePolicyMember(s, orgId, policyId, memberId)
//if err != nil {
//return
//}

//template := policyCheckTemplate
//if c.Bool(VFlag.Name) {
//template = policyCheckLTemplate
//}

//return DisplayStdOut(env, template,
//WithFunc("enabled", Enabled),
//WithData(struct {
//Enabled policy.Actions
//Actions []policies.ActionInfo
//}{
//member.Actions,
//itemRef.Type.AllActions(),
//}))
//}

//// ** RAW COMMANDS ** //

//var (
//policyCheckTemplate = `
//Supported Actions(Total={{len .Actions}}):

//{{ "#/action" | col 12 | header }}
//{{- range .Actions}}
//{{"*" | item}} {{ enabled $.Enabled .Action | mark }} {{ printf "%v" .Action | col 12 }}
//{{- end}}
//`

//policyCheckLTemplate = `
//Supported Actions(Total={{len .Actions}}):

//{{ "#/action" | col 12 | header }} {{ "#/description" | header }}
//{{- range .Actions}}
//{{"*" | item}} {{ enabled $.Enabled .Action | mark }} {{ printf "%v" .Action | col 12 }} {{ .Desc }}
//{{- end}}
//`
//)

//func Enabled(all policy.Actions, act policy.Action) string {
//if all.Enabled(policy.Sudo) || all.Enabled(act) {
//return OkMark
//} else {
//return ErrorMark
//}
//}

func ActionsFormatter(a policy.Actions) string {
	if len(a) == 0 {
		return "unauthorized"
	}
	if a.Enabled("sudo") {
		return "sudo"
	}
	return strings.Join(policy.ToStrings(a.Flatten()), ",")
}
