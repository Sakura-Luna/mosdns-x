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

package zone_file

import (
	"io"
	"os"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Matcher struct {
	m map[Question][]dns.RR
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (m *Matcher) LoadFile(s string) error {
	f, err := os.Open(s)
	if err != nil {
		return err
	}
	defer f.Close()

	return m.Load(f)
}

func (m *Matcher) Load(r io.Reader) error {
	if m.m == nil {
		m.m = make(map[Question][]dns.RR)
	}

	parser := dns.NewZoneParser(r, "", "")
	parser.SetDefaultTTL(3600)
	for {
		rr, ok := parser.Next()
		if !ok {
			break
		}
		h := rr.Header()
		q := Question{
			Name:  h.Name,
			Type:  dns.RRToType(rr),
			Class: h.Class,
		}
		m.m[q] = append(m.m[q], rr)
	}
	return parser.Err()
}

func (m *Matcher) Search(q Question) []dns.RR {
	return m.m[q]
}

func (m *Matcher) Reply(q *dns.Msg) *dns.Msg {
	var r *dns.Msg
	for _, quest := range q.Question {
		hdr := quest.Header()
		qt := Question{Name: hdr.Name, Type: dns.RRToType(quest), Class: hdr.Class}
		rr := m.Search(qt)
		if rr == nil {
			continue
		}
		if r == nil {
			r = new(dns.Msg)
			dnsutil.SetReply(r, q)
		}
		r.Answer = append(r.Answer, rr...)
	}
	return r
}
