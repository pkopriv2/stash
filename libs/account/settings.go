package account

import (
	"time"

	uuid "github.com/satori/go.uuid"
)

// Account settings are the account properties not managed by the
// account owner, but instead Iron administrators
type Settings struct {
	AccountId uuid.UUID `json:"account_id"`
	Version   int       `json:"version"`
	Enabled   bool      `json:"enabled"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	Phone     string    `json:"phone"`
	Email     string    `json:"email"`
}

func NewSettings(id uuid.UUID) Settings {
	now := time.Now().UTC()
	return Settings{
		AccountId: id,
		Enabled:   true,
		Created:   now,
		Updated:   now,
	}
}
