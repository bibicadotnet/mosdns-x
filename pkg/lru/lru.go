package lru

import (
	"fmt"

	"github.com/pmkol/mosdns-x/pkg/list"
)

type LRU[K comparable, V any] struct {
	maxSize int
	onEvict func(key K, v V)

	l *list.List[KV[K, V]]
	m map[K]*list.Elem[KV[K, V]]
}

type KV[K comparable, V any] struct {
	key K
	v   V
}

func NewLRU[K comparable, V any](maxSize int, onEvict func(key K, v V)) *LRU[K, V] {
	if maxSize <= 0 {
		panic(fmt.Sprintf("LRU: invalid max size: %d", maxSize))
	}

	return &LRU[K, V]{
		maxSize: maxSize,
		onEvict: onEvict,
		l:       list.New[KV[K, V]](),
		m:       make(map[K]*list.Elem[KV[K, V]], maxSize),
	}
}

func (q *LRU[K, V]) Add(key K, v V) {
	// Update existing
	if e, ok := q.m[key]; ok {
		e.Value.v = v
		q.l.MoveToBack(e)
		return
	}

	// Reuse oldest element if full (zero allocation path)
	if q.l.Len() >= q.maxSize {
		e := q.l.Front()

		if q.onEvict != nil {
			q.onEvict(e.Value.key, e.Value.v)
		}

		delete(q.m, e.Value.key)

		e.Value.key = key
		e.Value.v = v

		q.m[key] = e
		q.l.MoveToBack(e)
		return
	}

	// Normal allocation path
	e := list.NewElem(KV[K, V]{
		key: key,
		v:   v,
	})
	q.m[key] = e
	q.l.PushBack(e)
}

func (q *LRU[K, V]) Get(key K) (v V, ok bool) {
	e, ok := q.m[key]
	if !ok {
		return
	}
	q.l.MoveToBack(e)
	return e.Value.v, true
}

func (q *LRU[K, V]) Del(key K) {
	e := q.m[key]
	if e == nil {
		return
	}
	q.delElem(e)
}

func (q *LRU[K, V]) PopOldest() (key K, v V, ok bool) {
	e := q.l.Front()
	if e == nil {
		return
	}

	q.l.PopElem(e)
	delete(q.m, e.Value.key)

	key, v = e.Value.key, e.Value.v
	ok = true
	return
}

func (q *LRU[K, V]) Clean(f func(key K, v V) bool) (removed int) {
	e := q.l.Front()
	for e != nil {
		next := e.Next()
		key, v := e.Value.key, e.Value.v

		if f(key, v) {
			q.delElem(e)
			removed++
		}

		e = next
	}
	return
}

func (q *LRU[K, V]) Len() int {
	return q.l.Len()
}

func (q *LRU[K, V]) delElem(e *list.Elem[KV[K, V]]) {
	key, v := e.Value.key, e.Value.v
	q.l.PopElem(e)
	delete(q.m, key)

	if q.onEvict != nil {
		q.onEvict(key, v)
	}
}
