package client

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/path"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/libs/auth"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var (
	IdentityPrompt      = "Please enter your identity"
	PasswordResetPrompt = "Please enter your new password"
	PasswordPrompt      = "Please enter your password"
	VerifyPrompt        = "Please enter your verification code"
	IdentityInfo        = "Supports: email, user, pem, phone."
)

var empty auth.Identity

// ** COMMAND FLAGS ** //
var (
	LoginFlag = tool.StringFlag{
		Name:  "login-id",
		Usage: "The identity to use during login",
	}

	OrgFlag = tool.StringFlag{
		Name:  "org",
		Usage: "The org to use during login",
	}

	// Convenience aggregator (for use in individual commands)
	AuthFlags = tool.NewFlags(LoginFlag, OrgFlag)
)

var zero uuid.UUID

func LoadIdentity(env tool.Environment, str string) (ret auth.Identity, err error) {
	ret, err = auth.ParseFriendlyIdentity(str)
	if err != nil {
		return
	}

	if ret.Proto != auth.Pem {
		return
	}

	key, err := ReadPrivateKey(env, ret.Value())
	if err != nil {
		return
	}

	ret = auth.ByKey(key.Public())
	return
}

func ReadPrivateKey(env tool.Environment, file string) (ret crypto.PrivateKey, err error) {
	file, err = path.Expand(file)
	if err != nil {
		return
	}

	fmt, err := crypto.ReadPrivateKeyFormatFromFile(file)
	if err != nil {
		return
	}

	var decoder crypto.PemKeyDecoder
	switch fmt {
	default:
		err = errors.Wrapf(errs.ArgError, "Unsupported key type [%v]. Only support [PKCS1, PKCS8-Enc]", fmt)
		return
	case crypto.PKCS1:
		decoder = crypto.DecodePKCS1
	case crypto.PKCS8Encrypted:
		var pass []byte
		if err = env.Terminal.PromptPassword("Key Passphrase", &pass); err != nil {
			return
		}
		defer crypto.Bytes(pass).Destroy()
		decoder = crypto.NewEncryptedPKCS8Decoder(pass)
	}

	ret, err = crypto.ReadPrivateKeyFile(file, decoder)
	return
}

//func PromptIdentity(env tool.Environment) (string, error) {
//line, err := Prompt(env, IdentityPrompt,
//term.WithAutoInfo(
//term.StaticInfo(IdentityInfo)),
//term.WithAutoCheck(
//term.AllOk(
//term.NotEmpty(),
//term.NotLongerThan(64),
//term.NotShorterThan(4),
//term.OneOk(
//term.IsMatch(auth.IsPem, "*.pem"),
//term.IsMatch(auth.IsEmail, "user@example.io"),
//term.IsMatch(auth.IsUser, "@user"),
//term.IsMatch(auth.IsPhone, "xxx-xxx-xxxx"),
//),
//),
//))
//if err != nil {
//return "", nil
//}
//return line, nil
//}

//func LoadCredentials(e Environment, c *cli.Context, prompt string, ids ...string) (id auth.Identity, login auth.Login, err error) {

//// ** DETERMINE IDENTITY **
////
//// Precedence rules (Highest to Lowest):
////   * Pem file
////   * Email
////   * User
////
//if ident := c.String(LoginFlag.Name); ident != "" {
//id, err = auth.ParseFriendlyIdentity(env.ExpandPath(e, ident))
//if err != nil {
//return
//}
//}

//if len(ids) > 0 {
//id, err = auth.ParseFriendlyIdentity(env.ExpandPath(e, ids[0]))
//if err != nil {
//return
//}
//}

//var raw string // need to hold a reference to raw input in case its a pem file
//if id == empty {
//raw, err = PromptIdentity(e)
//if err != nil {
//return
//}

//id, err = auth.ParseFriendlyIdentity(env.ExpandPath(e, raw))
//if err != nil {
//return
//}
//}

//// ** DETERMINE CREDENTIAL/PASSPHRASE **
////
//// Precedence rules (Highest to Lowest):
////  * Flag
////  * Terminal
////
//switch id.Proto {
//default:
//err = errors.Wrapf(errs.ArgError, "Unsupported protocol [%v]", id.Proto)
//return
//case auth.User, auth.Email, auth.Phone, auth.Key:
//login = auth.WithTerminalPassword(e.Term(), prompt)
//return
//case auth.Pem:
//}

//var file string
//if pem := c.String(LoginFlag.Name); pem != "" {
//file = pem
//} else if len(ids) > 0 {
//file = ids[0]
//} else {
//file = raw
//}

//key, err := ReadPrivateKey(e, file)
//if err != nil {
//return
//}

//id, login = auth.ByKey(key.Public()), auth.WithSignature(key, e.Conf().GetStrength())
//return
//}
