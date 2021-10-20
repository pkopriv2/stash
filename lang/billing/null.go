package billing

type NullClient struct {
}

func NewNullClient() Client {
	return NullClient{}
}

func (n NullClient) PublicKey() (ret string) {
	return
}

func (n NullClient) NewPaymentToken(p Payment) (ret string, err error) {
	return
}

func (n NullClient) NewCustomer(email, token string) (ret Customer, err error) {
	return
}

func (n NullClient) UpdateCustomer(Customer) (err error) {
	return
}

func (n NullClient) GetCustomer(id string) (ret Customer, ok bool, err error) {
	return
}

func (n NullClient) NewSubscription(customerId string, i []Item) (id string, err error) {
	return
}

func (n NullClient) CancelSubscription(subId string) (err error) {
	return
}

func (n NullClient) ListInvoices(subId string, startId *string, max int64) (ret []Invoice, err error) {
	return
}

func (n NullClient) NextInvoice(_, _ string) (ret Invoice, err error) {
	return
}

func (n NullClient) UpdateSubscription(subId string, items []Item) (err error) {
	return
}
