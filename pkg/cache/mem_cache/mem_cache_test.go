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

package mem_cache

import (
	"sync"
	"testing"
	"time"
)

func Test_memCache(t *testing.T) {
	c := NewMemCache(1024, 0)
	for i := 0; i < 128; i++ {
		key := uint64(i)
		now := time.Now().Unix()
		c.Store(key, []byte{byte(i)}, now, now+1)
		v, _, _ := c.Get(key)

		if v[0] != byte(i) {
			t.Fatal("cache kv mismatched")
		}
	}

	for i := 0; i < 1024*4; i++ {
		key := uint64(i)
		now := time.Now().Unix()
		c.Store(key, []byte{}, now, now+1)
	}

	if c.Len() > 2048 {
		t.Fatal("cache overflow")
	}
}

func Test_memCache_cleaner(t *testing.T) {
	c := NewMemCache(1024, time.Millisecond*10)
	defer c.Close()
	for i := 0; i < 64; i++ {
		key := uint64(i)
		now := time.Now().Unix()
		c.Store(key, make([]byte, 0), now, now) // Expired immediately
	}

	time.Sleep(time.Millisecond * 100)
	if c.Len() != 0 {
		t.Fatal()
	}
}

func Test_memCache_race(t *testing.T) {
	c := NewMemCache(1024, -1)
	defer c.Close()

	wg := sync.WaitGroup{}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 256; i++ {
				key := uint64(i)
				now := time.Now().Unix()
				c.Store(key, []byte{}, now, now+60)
				_, _, _ = c.Get(key)
				c.lru.Clean(func(_ uint64, _ *elem) bool { return false })
			}
		}()
	}
	wg.Wait()
}
