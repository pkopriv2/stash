package server

import (
	"bytes"
	"os"
	"os/signal"
	"syscall"

	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/http/server/httpaccount"
	"github.com/cott-io/stash/http/server/httporg"
	"github.com/cott-io/stash/http/server/httppolicy"
	"github.com/cott-io/stash/http/server/httpsecret"
	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/lang/mail"
	"github.com/cott-io/stash/lang/net"
	"github.com/cott-io/stash/lang/sms"
	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/lang/tool"
	"github.com/cott-io/stash/sql/sqlaccount"
	"github.com/cott-io/stash/sql/sqlorg"
	"github.com/cott-io/stash/sql/sqlpolicy"
	"github.com/cott-io/stash/sql/sqlsecret"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var (
	DefaultHandlers = []http.ServiceBuilder{
		httpaccount.Handlers,
		httporg.Handlers,
		httppolicy.Handlers,
		httpsecret.Handlers,
	}
)

var (
	AddrFlag = tool.StringFlag{
		Name:    "addr",
		Usage:   "The address to bind",
		Default: ":8080",
	}

	LoggingFlag = tool.StringFlag{
		Name:    "logging",
		Usage:   "Set the log level (Debug, Info, Error, Off)",
		Default: "Info",
	}

	RunCommand = tool.NewCommand(
		tool.CommandDef{
			Name:  "run",
			Usage: "run",
			Info:  "Runs a server instance",
			Help: `
Starts a local server.

Examples:

	$ stash run
`,
			Flags: tool.NewFlags(AddrFlag, LoggingFlag),
			Exec:  ServerRun,
		})
)

func ServerRun(env tool.Environment, c *cli.Context) (err error) {
	key, err := getSigningKey(env)
	if err != nil {
		return
	}
	env.Context.Logger().Info("Using signing key [%v]", key.Public().ID())

	mailer, err := getMailer(env)
	if err != nil {
		return
	}

	texter, err := getTexter(env)
	if err != nil {
		return
	}

	biller, billingKey, err := getBiller(env)
	if err != nil {
		return
	}

	driver, err := getSqlDriver(env)
	if err != nil {
		return
	}
	defer driver.Close()

	registry := sql.NewSchemaRegistry("STASH")
	if err != nil {
		return
	}

	accounts, err := sqlaccount.NewSqlStore(driver, registry)
	if err != nil {
		return
	}

	orgs, err := sqlorg.NewSqlStore(driver, registry)
	if err != nil {
		return
	}

	policies, err := sqlpolicy.NewSqlStore(driver, registry)
	if err != nil {
		return
	}

	secrets, err := sqlsecret.NewSqlStore(driver, registry)
	if err != nil {
		return
	}

	server, err := http.Serve(env.Context,
		http.Build(DefaultHandlers...),
		http.WithListener(&net.TCP4Network{}, c.String(AddrFlag.Name)),
		http.WithDependency(core.Accounts, accounts),
		http.WithDependency(core.Orgs, orgs),
		http.WithDependency(core.Policies, policies),
		http.WithDependency(core.Secrets, secrets),
		http.WithDependency(core.BillingKey, billingKey),
		http.WithDependency(core.Biller, biller),
		http.WithDependency(core.Mailer, mailer),
		http.WithDependency(core.Texter, texter),
		http.WithDependency(core.Signer, key),
		http.WithMiddleware(http.TimerMiddleware),
		http.WithMiddleware(http.RouteMiddleware))
	if err != nil {
		return
	}
	defer server.Close()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return
}

// FIXME: Server signing key should be managed in the database!
func getSigningKey(env tool.Environment) (ret crypto.PrivateKey, err error) {
	pem := os.Getenv("STASH_SIGNING_KEY")
	if pem != "" {
		env.Context.Logger().Debug("Decoding private key from string literal")
		ret, err = crypto.ReadPrivateKey(bytes.NewBuffer([]byte(pem)), crypto.DecodePKCS1)
		return
	}

	env.Context.Logger().Debug("Randomly generating key")
	ret, err = crypto.GenRSAKey(crypto.Rand, crypto.Strong.KeySize())
	return
}

func getSqlDriver(env tool.Environment) (ret sql.Driver, err error) {
	dbDriver := os.Getenv("STASH_DB_DRIVER")
	switch dbDriver {
	default:
		err = errors.Wrapf(errs.ArgError, "Invalid value for STASH_DB_DRIVER [%v]. Expected ['sqlite','postgres','<empty>']", dbDriver)
	case "", "sqlite":
		ret, err = dialSqlite(env)
		//case "postgres":
		//ret, err = dialPostgres(env)
	}
	return
}

func dialSqlite(env tool.Environment) (ret sql.Driver, err error) {
	dbAddr := os.Getenv("STASH_DB_ADDR")
	switch dbAddr {
	case "", ":memory:":
		env.Context.Logger().Info("Using in-memory sqlite instance")
		ret, err = sql.NewSqlLiteDialer().Embed(env.Context)
		return
	}

	env.Context.Logger().Info("Using sqlite driver [%v]", dbAddr)
	ret, err = sql.NewSqlLiteDialer().Connect(env.Context, dbAddr)
	return
}

//func dialPostgres(env tool.Environment, ctx context.Context) (ret sqlx.Driver, err error) {
//dbAddr, ok := env.Var("STASH_DB_ADDR")
//if !ok {
//err = errors.Wrapf(errs.ArgError, "Missing required value for STASH_DB_ADDR")
//return
//}

//dbUser, ok := env.Var("STASH_DB_USER")
//if !ok {
//err = errors.Wrapf(errs.ArgError, "Missing required value for STASH_DB_USER")
//return
//}

//dbPass, ok := env.Var("STASH_DB_PASS")
//if !ok {
//err = errors.Wrapf(errs.ArgError, "Missing required value for STASH_DB_PASS")
//return
//}

//ctx.Logger().Info("Using postgres driver [%v]", dbAddr)

//dbMaxOpenConns := -1
//if str, ok := env.Var("STASH_DB_MAX_OPEN_CONNS"); ok {
//dbMaxOpenConns, err = strconv.Atoi(str)
//if err != nil {
//return nil, err
//}
//}
//ctx.Logger().Info("Setting max open conns to [%v]", dbMaxOpenConns)

//dbMaxConnLifetime := time.Duration(-1)
//if str, ok := env.Var("STASH_DB_MAX_CONN_LIFETIME"); ok {
//dbMaxConnLifetime, err = time.ParseDuration(str)
//if err != nil {
//return nil, err
//}
//}
//ctx.Logger().Info("Setting max idle conn lifetime to [%v]", dbMaxConnLifetime)

//dbMaxIdleConns := -1
//if str, ok := env.Var("STASH_DB_MAX_IDLE_CONNS"); ok {
//dbMaxIdleConns, err = strconv.Atoi(str)
//if err != nil {
//return nil, err
//}
//}
//ctx.Logger().Info("Setting max idle conns to [%v]", dbMaxIdleConns)

//ret, err = sqlx.NewPostgresDialer().Connect(ctx, fmt.Sprintf("postgres://%v:%v@%v", dbUser, dbPass, dbAddr), func(o *sqlx.Options) {
//if dbMaxOpenConns != -1 {
//o.MaxOpenConns = &dbMaxOpenConns
//}
//if dbMaxIdleConns != -1 {
//o.MaxIdleConns = &dbMaxIdleConns
//}
//if dbMaxConnLifetime != -1 {
//o.MaxConnLifetime = &dbMaxConnLifetime
//}
//})
//return
//}

func getMailer(env tool.Environment) (ret mail.Client, err error) {
	mxDomain := os.Getenv("STASH_MX_DOMAIN")
	mxPubKey := os.Getenv("STASH_MX_PUBKEY")
	mxApiKey := os.Getenv("STASH_MX_APIKEY")
	if mxDomain == "" || mxPubKey == "" || mxApiKey == "" {
		env.Context.Logger().Info("Mail disabled")
		ret = mail.NewMemClient()
		return
	}

	env.Context.Logger().Info("Using mailgun client [%v] with public key [%v]", mxDomain, mxPubKey)
	ret = mail.NewMailGunClient(mxDomain, mxApiKey, mxPubKey, []string{})
	return
}

func getBiller(env tool.Environment) (ret billing.Client, pubKey string, err error) {
	apiKey := os.Getenv("STASH_CC_APIKEY")
	pubKey = os.Getenv("STASH_CC_PUBKEY")
	if apiKey == "" || pubKey == "" {
		env.Context.Logger().Debug("Billing disabled")
		ret = billing.NewNullClient()
		return
	}

	env.Context.Logger().Info("Using stripe billing")
	ret = billing.NewStripeClient(apiKey)
	return
}

func getTexter(env tool.Environment) (ret sms.Client, err error) {
	smsNumber := os.Getenv("STASH_SMS_NUMBER")
	smsAppId := os.Getenv("STASH_SMS_APPSID")
	smsToken := os.Getenv("STASH_SMS_TOKEN")
	if smsNumber == "" || smsAppId == "" || smsToken == "" {
		env.Context.Logger().Info("Texting disabled")
		ret = sms.NewMemClient()
		return
	}

	env.Context.Logger().Info("Using twilio client [%v]", smsNumber)
	ret = sms.NewTwilioClient(smsNumber, smsAppId, smsToken)
	return
}
