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

package fastforward

import (
	"context"
	"net"
	"time"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"

	"codeberg.org/miekg/dns"
)

type udpmeUpstream struct {
	addr    string
	trusted bool
}

func newUDPME(addr string, trusted bool) *udpmeUpstream {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &udpmeUpstream{addr: addr, trusted: trusted}
}

func (u *udpmeUpstream) Address() string {
	return u.addr
}

func (u *udpmeUpstream) IPAddress() string {
	return ""
}

func (u *udpmeUpstream) Trusted() bool {
	return u.trusted
}

func (u *udpmeUpstream) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	timeout := time.Second * 3
	if ddl, ok := ctx.Deadline(); ok {
		timeout = ddl.Sub(time.Now())
	}

	EDNSFlag := m.IsEdns0()
	if !EDNSFlag {
		m = m.Copy()
		m.UDPSize = 1232
	}
	r, e := u.exchangeOPTM(m, timeout)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case e != nil:
		return nil, e
	default:
		if !EDNSFlag {
			dnsutils.RemoveEDNS0(r)
		}
		return r, nil
	}
}

func (u *udpmeUpstream) exchangeOPTM(m *dns.Msg, dur time.Duration) (*dns.Msg, error) {
	c, err := net.DialTimeout("udp", u.addr, dur)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	m.Pack()
	conn := dnsutils.Conn{Conn: c}
	if err = conn.WriteMsg(m); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	for {
		r, err := conn.ReadMsg(buf)
		if err != nil {
			return nil, err
		}
		if !dnsutils.IsEdnsResp(r) {
			continue
		}
		return r, nil
	}
}
