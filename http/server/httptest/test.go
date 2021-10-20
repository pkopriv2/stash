package httptest

import (
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/http/server/httpaccount"
	"github.com/cott-io/stash/http/server/httporg"
	"github.com/cott-io/stash/http/server/httppolicy"
	"github.com/cott-io/stash/http/server/httpsecret"
	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/lang/mail"
	"github.com/cott-io/stash/lang/sql"
	"github.com/cott-io/stash/sql/sqlaccount"
	"github.com/cott-io/stash/sql/sqlorg"
	"github.com/cott-io/stash/sql/sqlpolicy"
	"github.com/cott-io/stash/sql/sqlsecret"
)

var (
	DefaultHandlers = []http.ServiceBuilder{
		httpaccount.Handlers,
		httporg.Handlers,
		httppolicy.Handlers,
		httpsecret.Handlers,
	}
)

func StartDefaultServer(ctx context.Context, opts ...http.Option) (ret *http.Server, err error) {
	ret, err = StartServer(ctx, DefaultHandlers, opts...)
	return
}

func StartServer(ctx context.Context, handlers []http.ServiceBuilder, opts ...http.Option) (ret *http.Server, err error) {

	driver, err := sql.NewSqlLiteDialer().Embed(ctx)
	if err != nil {
		return
	}
	schema := sql.NewSchemaRegistry("TEST")

	accounts, err := sqlaccount.NewSqlStore(driver, schema)
	if err != nil {
		return
	}

	orgs, err := sqlorg.NewSqlStore(driver, schema)
	if err != nil {
		return
	}

	policies, err := sqlpolicy.NewSqlStore(driver, schema)
	if err != nil {
		return
	}

	secrets, err := sqlsecret.NewSqlStore(driver, schema)
	if err != nil {
		return
	}

	key, err := crypto.GenRSAKey(crypto.Rand, 1024)
	if err != nil {
		return
	}

	ret, err = http.Serve(ctx,
		http.Build(handlers...),
		append([]http.Option{
			http.WithDependency(core.Accounts, accounts),
			http.WithDependency(core.Orgs, orgs),
			http.WithDependency(core.Policies, policies),
			http.WithDependency(core.Secrets, secrets),
			http.WithDependency(core.BillingKey, ""),
			http.WithDependency(core.Biller, billing.NullClient{}),
			http.WithDependency(core.Mailer, mail.MemClient{}),
			http.WithDependency(core.Signer, key),
			http.WithMiddleware(http.TimerMiddleware),
			http.WithMiddleware(http.RouteMiddleware)}, opts...)...)
	return
}
