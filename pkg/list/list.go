package list

type List[V any] struct {
	front, back *Elem[V]
	length      int
}

func New[V any]() *List[V] {
	return &List[V]{}
}

func (l *List[V]) Front() *Elem[V] {
	return l.front
}

func (l *List[V]) Back() *Elem[V] {
	return l.back
}

func (l *List[V]) Len() int {
	return l.length
}

func (l *List[V]) PushFront(e *Elem[V]) *Elem[V] {
	l.length++
	e.list = l

	if l.front == nil {
		l.front = e
		l.back = e
		return e
	}

	e.next = l.front
	l.front.prev = e
	l.front = e
	return e
}

func (l *List[V]) PushBack(e *Elem[V]) *Elem[V] {
	l.length++
	e.list = l

	if l.back == nil {
		l.front = e
		l.back = e
		return e
	}

	e.prev = l.back
	l.back.next = e
	l.back = e
	return e
}

// MoveToBack moves an existing element to the back in O(1).
// Does not change length.
func (l *List[V]) MoveToBack(e *Elem[V]) {
	if e.list != l {
		panic("elem does not belong to this list")
	}

	if l.back == e {
		return
	}

	p, n := e.prev, e.next

	// detach
	if p != nil {
		p.next = n
	} else {
		l.front = n
	}

	if n != nil {
		n.prev = p
	}

	// attach at back
	e.prev = l.back
	e.next = nil

	l.back.next = e
	l.back = e
}

func (l *List[V]) PopElem(e *Elem[V]) *Elem[V] {
	if e.list != l {
		panic("elem does not belong to this list")
	}

	l.length--

	p, n := e.prev, e.next

	if p != nil {
		p.next = n
	} else {
		l.front = n
	}

	if n != nil {
		n.prev = p
	} else {
		l.back = p
	}

	e.prev = nil
	e.next = nil
	e.list = nil

	return e
}
