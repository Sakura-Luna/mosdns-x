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

package bundled_upstream

import (
	"context"
	"errors"
	"sync"

	"codeberg.org/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/query_context"
)

type Upstream interface {
	// Exchange sends q to the upstream and waits for response.
	// If any error occurs. Implements must return a nil msg with a non nil error.
	// Otherwise, Implements must a msg with nil error.
	Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error)

	// Trusted indicates whether this Upstream is trusted/reliable.
	// If true, responses from this Upstream will be accepted without checking its rcode.
	Trusted() bool

	Address() string
	IPAddress() string
}

type parallelResult struct {
	r    *dns.Msg
	err  error
	from Upstream
}

var nopLogger = zap.NewNop()

func ExchangeParallel(ctx context.Context, qCtx *query_context.Context, upstreams []Upstream, logger *zap.Logger) (*dns.Msg, error, string) {
	if logger == nil {
		logger = nopLogger
	}

	q := qCtx.Q()
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	c := make(chan *parallelResult, len(upstreams)) // use buf chan to avoid blocking.
	for _, u := range upstreams {
		u := u
		qCopy := q.Copy() // qCtx is not safe for concurrent use.

		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := u.Exchange(taskCtx, qCopy)

			select {
			case c <- &parallelResult{r: r, err: err, from: u}:
			case <-taskCtx.Done():
				return
			}
		}()
	}
	go func() {
		wg.Wait()
		close(c)
	}()

	var err error
	for range upstreams {
		select {
		case <-taskCtx.Done():
			return nil, taskCtx.Err(), ""

		case res := <-c:
			if res.err != nil {
				switch {
				case !errors.Is(res.err, context.Canceled):
					msg := []zap.Field{qCtx.InfoField(), zap.String("addr", res.from.Address())}
					if ip := res.from.IPAddress(); ip != "" {
						msg = append(msg, zap.String("ip", ip))
					}
					logger.Warn("upstream", append(msg, zap.Error(res.err))...)
					err = res.err
				case err == nil:
					err = res.err
				}
				continue
			}

			if res.r != nil && (res.from.Trusted() || res.r.Rcode == dns.RcodeSuccess) {
				cancel()
				return res.r, nil, res.from.Address()
			}
		}
	}
	return nil, err, ""
}
