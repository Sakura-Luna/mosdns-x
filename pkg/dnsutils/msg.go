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

package dnsutils

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// GetMinimalTTL returns the minimal ttl of this msg.
// If msg m has no record, it returns 0.
func GetMinimalTTL(m *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	hasRecord := false
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hasRecord = true
			ttl := rr.Header().TTL
			if ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	if !hasRecord { // no ttl applied
		return 0
	}
	return minTTL
}

// SetTTL updates all records' ttl to ttl, except opt record.
func SetTTL(m *dns.Msg, ttl uint32) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			rr.Header().TTL = ttl
		}
	}
}

// SubtractTTL subtract delta from every m's RR.
// If RR's TTL is smaller than delta, SubtractTTL
// will return overflowed = true.
func SubtractTTL(m *dns.Msg, delta uint32) (overflowed bool) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if ttl := hdr.TTL; ttl > delta {
				hdr.TTL = ttl - delta
			} else {
				hdr.TTL = 1
				overflowed = true
			}
		}
	}
	return
}

func ApplyTTL(m *dns.Msg, max uint32, min uint32) {
	for _, section := range [...][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if max > 0 && hdr.TTL > max {
				hdr.TTL = max
			} else if min > 0 && hdr.TTL < min {
				hdr.TTL = min
			}
		}
	}
}

func GenEmptyReply(q *dns.Msg, rcode uint16) *dns.Msg {
	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	r.Rcode = rcode
	r.RecursionAvailable = true

	var name string
	if len(q.Question) > 1 {
		name = q.Question[0].Header().Name
	} else {
		name = "."
	}

	r.Ns = []dns.RR{FakeSOA(name)}
	return r
}

func FakeSOA(name string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.Header{
			Name:  name,
			Class: dns.ClassINET,
			TTL:   300,
		},
		SOA: rdata.SOA{
			Ns:      "fake-ns.mosdns.fake.root.",
			Mbox:    "fake-mbox.mosdns.fake.root.",
			Serial:  2021110400,
			Refresh: 1800,
			Retry:   900,
			Expire:  604800,
			Minttl:  86400,
		},
	}
}

// GetMsgKey unpacks m and set its id to salt.
func GetMsgKey(m *dns.Msg, salt uint16) (string, error) {
	err := m.Pack()
	if err != nil {
		return "", err
	}
	wireMsg := m.Data
	wireMsg[0] = byte(salt >> 8)
	wireMsg[1] = byte(salt)
	return string(wireMsg), nil
}

// // GetMsgKeyWithBytesSalt unpacks m and appends salt to the string.
// func GetMsgKeyWithBytesSalt(m *dns.Msg, salt []byte) (string, error) {
// 	wireMsg, buf, err := pool.PackBuffer(m)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer buf.Release()
//
// 	wireMsg[0] = 0
// 	wireMsg[1] = 0
//
// 	sb := new(strings.Builder)
// 	sb.Grow(len(wireMsg) + len(salt))
// 	sb.Write(wireMsg)
// 	sb.Write(salt)
//
// 	return sb.String(), nil
// }
//
// // GetMsgKeyWithInt64Salt unpacks m and appends salt to the string.
// func GetMsgKeyWithInt64Salt(m *dns.Msg, salt int64) (string, error) {
// 	b := make([]byte, 8)
// 	binary.BigEndian.PutUint64(b, uint64(salt))
// 	return GetMsgKeyWithBytesSalt(m, b)
// }
