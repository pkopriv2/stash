package page

type PageOption func(*Page)

// The paging options
type Page struct {
	AfterId *string `json:"after_id,omitempty"`
	Offset  *uint64 `json:"offset,omitempty"`
	Limit   *uint64 `json:"limit,omitempty"`
	OrderBy *string `json:"order_by,omitempty"`
	Desc    *bool   `json:"desc,omitempty"`
}

func BuildPage(fns ...PageOption) (ret Page) {
	for _, fn := range fns {
		fn(&ret)
	}
	return
}

func Limit(num uint64) PageOption {
	return func(o *Page) {
		o.Limit = &num
	}
}

func LimitPtr(num *uint64) PageOption {
	return func(o *Page) {
		o.Limit = num
	}
}

func Offset(num uint64) PageOption {
	return func(o *Page) {
		o.Offset = &num
	}
}

func OffsetPtr(num *uint64) PageOption {
	return func(o *Page) {
		o.Offset = num
	}
}
