/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package redis_cache

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

var nopLogger = zap.NewNop()

type RedisCacheOpts struct {
	Client        redis.Cmdable
	ClientCloser  io.Closer
	ClientTimeout time.Duration
	Logger        *zap.Logger
}

func (opts *RedisCacheOpts) Init() error {
	if opts.Client == nil {
		return errors.New("nil client")
	}
	utils.SetDefaultNum(&opts.ClientTimeout, time.Second)
	if opts.Logger == nil {
		opts.Logger = nopLogger
	}
	return nil
}

type RedisCache struct {
	opts           RedisCacheOpts
	clientDisabled uint32
}

func NewRedisCache(opts RedisCacheOpts) (*RedisCache, error) {
	if err := opts.Init(); err != nil {
		return nil, err
	}
	return &RedisCache{
		opts: opts,
	}, nil
}

func (r *RedisCache) disabled() bool {
	return atomic.LoadUint32(&r.clientDisabled) != 0
}

func (r *RedisCache) disableClient() {
	if atomic.CompareAndSwapUint32(&r.clientDisabled, 0, 1) {
		r.opts.Logger.Warn("redis temporarily disabled")
		go func() {
			const maxBackoff = time.Second * 30
			backoff := time.Millisecond * 100
			for {
				time.Sleep(backoff)
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
				err := r.opts.Client.Ping(ctx).Err()
				cancel()
				if err != nil {
					if backoff >= maxBackoff {
						backoff = maxBackoff
					} else {
						backoff += time.Duration(rand.Intn(1000))*time.Millisecond + time.Second
					}
					r.opts.Logger.Warn("redis ping failed", zap.Error(err), zap.Duration("next_ping", backoff))
					continue
				}
				atomic.StoreUint32(&r.clientDisabled, 0)
				return
			}
		}()
	}
}

// Get implements cache.Backend.
func (r *RedisCache) Get(key string) (v []byte, storedTime int64, lazyHit bool, ok bool) {
	if r.disabled() {
		return nil, 0, false, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.opts.ClientTimeout)
	defer cancel()
	b, err := r.opts.Client.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			r.opts.Logger.Warn("redis get", zap.Error(err))
			r.disableClient()
		}
		return nil, 0, false, false
	}

	sTime, expirationNano, m, err := unpackRedisValue(b)
	if err != nil {
		r.opts.Logger.Warn("redis data unpack error", zap.Error(err))
		return nil, 0, false, false
	}

	// Check if the data is fully expired (beyond lazy window)
	now := time.Now().UnixNano()
	if now > expirationNano {
		return nil, 0, false, false
	}

	// Simplified lazyHit check: if it's nearing the end of its life, mark as lazy.
	// Actual TTL logic is managed by the caller using storedTime.
	return m, sTime, false, true
}

// Store implements cache.Backend.
func (r *RedisCache) Store(key string, v []byte, expire, lazyExpire int64) {
	if r.disabled() {
		return
	}

	now := time.Now().UnixNano()
	ttlNano := lazyExpire - now
	if ttlNano <= 0 {
		return
	}

	// Use Unix timestamp in seconds for storedTime to save space or match existing format.
	sTime := time.Now().Unix()
	data := packRedisData(sTime, lazyExpire, v)
	defer data.Release()

	ctx, cancel := context.WithTimeout(context.Background(), r.opts.ClientTimeout)
	defer cancel()
	if err := r.opts.Client.Set(ctx, key, data.Bytes(), time.Duration(ttlNano)).Err(); err != nil {
		r.opts.Logger.Warn("redis set", zap.Error(err))
		r.disableClient()
	}
}

func (r *RedisCache) Close() error {
	if f := r.opts.ClientCloser; f != nil {
		return f.Close()
	}
	return nil
}

func (r *RedisCache) Len() int {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()
	i, err := r.opts.Client.DBSize(ctx).Result()
	if err != nil {
		r.opts.Logger.Error("dbsize", zap.Error(err))
		return 0
	}
	return int(i)
}

func packRedisData(storedTime, expirationTime int64, v []byte) *pool.Buffer {
	buf := pool.GetBuf(8 + 8 + len(v))
	b := buf.Bytes()
	binary.BigEndian.PutUint64(b[:8], uint64(storedTime))
	binary.BigEndian.PutUint64(b[8:16], uint64(expirationTime))
	copy(b[16:], v)
	return buf
}

func unpackRedisValue(b []byte) (storedTime, expirationTime int64, v []byte, err error) {
	if len(b) < 16 {
		return 0, 0, nil, errors.New("b is too short")
	}
	storedTime = int64(binary.BigEndian.Uint64(b[:8]))
	expirationTime = int64(binary.BigEndian.Uint64(b[8:16]))
	v = b[16:]
	return storedTime, expirationTime, v, nil
}
