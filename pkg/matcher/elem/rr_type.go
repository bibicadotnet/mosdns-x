/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package elem

type matcher interface {
	Match(int) bool
}

type bitmask64Matcher uint64

func (b bitmask64Matcher) Match(v int) bool {
	if uint(v) > 63 {
		return false
	}
	return (uint64(b) & (1 << v)) != 0
}

type bitmask128Matcher [2]uint64

func (b *bitmask128Matcher) Match(v int) bool {
	if uint(v) > 127 {
		return false
	}

	idx := v >> 6
	bit := v & 63

	return (b[idx] & (1 << bit)) != 0
}

type sliceMatcher []int

func (s sliceMatcher) Match(v int) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

type mapMatcher map[int]struct{}

func (m mapMatcher) Match(v int) bool {
	_, ok := m[v]
	return ok
}

type IntMatcher struct {
	impl matcher
}

func (im *IntMatcher) Match(v int) bool {
	return im.impl.Match(v)
}

func NewIntMatcher(elem []int) *IntMatcher {
	return &IntMatcher{
		impl: newMatcherImpl(elem),
	}
}

func newMatcherImpl(elem []int) matcher {
	if len(elem) == 0 {
		return sliceMatcher{}
	}

	var maxVal int
	var minVal int

	for i, v := range elem {
		if i == 0 {
			minVal, maxVal = v, v
		} else {
			if v > maxVal {
				maxVal = v
			}
			if v < minVal {
				minVal = v
			}
		}
	}

	if minVal >= 0 && maxVal <= 63 {
		var mask uint64
		for _, v := range elem {
			mask |= 1 << v
		}
		return bitmask64Matcher(mask)
	}

	if minVal >= 0 && maxVal <= 127 {
		m := new(bitmask128Matcher)
		for _, v := range elem {
			m[v>>6] |= 1 << (v & 63)
		}
		return m
	}

	if len(elem) <= 16 {
		s := make(sliceMatcher, len(elem))
		copy(s, elem)
		return s
	}

	m := make(mapMatcher, len(elem))
	for _, v := range elem {
		m[v] = struct{}{}
	}
	return m
}
