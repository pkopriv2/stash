package billing

import (
	"errors"
	"time"
)

// ** BILLING INTERFACES AND UTILITIES ** //

var (
	ErrPayment = errors.New("Billing:Payment")
)

// Split out common form from exact form for forwards compatibility
type Plan string

const (
	Users  Plan = "Users"
	Agents Plan = "Agents"
)

type Client interface {

	// Creates a new payment token.  Payment tokens are a way to encode
	// credit card details without leaking those details to any external
	// systems - including ours.  Payment tokens should be generated only
	// in client-side code, using only public keys.
	NewPaymentToken(p Payment) (string, error)

	// Creates a new customer from the external billing system.
	NewCustomer(email, token string) (Customer, error)

	// Updates a consumer.
	UpdateCustomer(Customer) error

	// Retrieves a customer from the external billing system.
	GetCustomer(id string) (Customer, bool, error)

	// Creates a subscription for a customer. (this should use local tokenizing as per PCI compliance)
	NewSubscription(customerId string, items []Item) (id string, err error)

	// Updates a subscription with a new plan and quantity
	UpdateSubscription(subId string, items []Item) (err error)

	// Creates a new card for a customer. (this should use local tokenizing as per PCI compliance)
	CancelSubscription(subId string) (err error)

	// Retrieve the next invoice.  This is a pending invoice and only
	// reflects what will be charged.  This may not be paid until its due date.
	NextInvoice(customerId, subId string) (Invoice, error)

	// List the invoices for a subscription.  The startId is optional and is the id of the
	// first invoice to receive (useful for pagination)
	ListInvoices(subId string, startId *string, max int64) ([]Invoice, error)
}

type Customer struct {
	Id      string  `json:"id"`
	Email   string  `json:"email"`
	Payment Payment `json:"payment"`
}

type Card struct {
	// Required for actually paying!
	Name   string `json:"name"`
	Number string `json:"number"`
	Month  string `json:"month"`
	Year   string `json:"year"`
	CVC    string `json:"cvc"`
	Zip    string `json:"zip"`

	// Optional.  Used for display only.
	Brand string `json:"brand,omitempty"`
	Last4 string `json:"last4,omitempty"`
}

type Item struct {
	Plan     Plan  `json:"plan"`
	Quantity int64 `json:"quantity"`
}

type Payment struct {
	Card  *Card   `json:"-"`
	Token *string `json:"token"`
}

type Invoice struct {
	Id           string    `json:"id"`
	CustomerId   string    `json:"x_customer_id"`
	SubId        string    `json:"x_subscription_id"`
	Date         time.Time `json:"date"`
	DueDate      time.Time `json:"due_date"`
	Desc         string    `json:"description"`
	Paid         bool      `json:"paid"`
	PeriodStart  time.Time `json:"period_start"`
	PeriodEnd    time.Time `json:"period_end"`
	BalanceStart int64     `json:"balance_start"`
	BalanceEnd   int64     `json:"balance_end"`
	Subtotal     int64     `json:"sub_total"`
	Tax          int64     `json:"tax"`
	TaxPercent   float64   `json:"tax_percent"`
	Total        int64     `json:"total"`
}
