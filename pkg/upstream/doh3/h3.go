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

package doh3

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/singleflight"

	C "github.com/pmkol/mosdns-x/constant"
)

type Upstream struct {
	url       *url.URL
	transport *http3.Transport
}

func NewUpstream(url *url.URL, transport *http3.Transport) *Upstream {
	return &Upstream{url, transport}
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	// q.Id = 0
	err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url.String(), q)
	if err != nil {
		return nil, err
	}
	C.MakeHeader(req)

	var group singleflight.Group
	res, err := u.transport.RoundTrip(req)
	if err != nil {
		if strings.HasSuffix(err.Error(), "0-RTT rejected") {
			group.Do("refresh", func() (any, error) {
				tlsConf := u.transport.TLSClientConfig.Clone()
				tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(64)
				u.transport.TLSClientConfig = tlsConf
				return nil, nil
			})
		}
		return nil, err
	}
	defer res.Body.Close()
	if err = C.DealResponse(res); err != nil {
		return nil, err
	}

	r := new(dns.Msg)
	r.Data, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = r.Unpack()
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return u.transport.Close()
}
