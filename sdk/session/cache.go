package session

import (
	"reflect"
	"time"

	"github.com/cott-io/stash/lang/errs"
	"github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
)

type cacheItem struct {
	raw interface{}
	exp time.Time
}

type Cache interface {
	Get(string, interface{}) (bool, error)
	Set(string, interface{}, time.Duration) error
	Del(string) error
}

type LRUCache struct {
	raw *lru.Cache
}

func NewLRUCache(max int) LRUCache {
	raw, err := lru.New(max)
	if err != nil {
		panic(err)
	}
	return LRUCache{raw}
}

func (l LRUCache) Close() (err error) {
	return
}

func (l LRUCache) Get(name string, ptr interface{}) (ok bool, err error) {
	val, ok := l.raw.Get(name)
	if !ok {
		return
	}

	item := val.(cacheItem)
	if time.Now().After(item.exp) {
		l.raw.Remove(name)
		return
	}

	refPtr, refVal :=
		reflect.ValueOf(ptr),
		reflect.ValueOf(item.raw)
	if refPtr.Kind() != reflect.Ptr {
		err = errors.Wrapf(errs.ArgError, "Expected a pointer [%v]", ptr)
		return
	}

	refPtr.Elem().Set(refVal)
	return
}

func (l LRUCache) Set(name string, val interface{}, ttl time.Duration) (err error) {
	l.raw.Add(name, cacheItem{val, time.Now().Add(ttl)})
	return
}

func (l LRUCache) Del(name string) (err error) {
	l.raw.Remove(name)
	return
}

type noCache struct{}

func (n noCache) Close() (err error) {
	return
}

func (n noCache) Get(string, interface{}) (ok bool, err error) {
	return
}

func (n noCache) Set(string, interface{}, time.Duration) (err error) {
	return
}

func (n noCache) Del(string) (err error) {
	return
}
