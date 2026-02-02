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

package hosts

import (
	"bytes"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/matcher/domain"
)

var testHosts = `
# comment
     # empty line
dns.google 8.8.8.8 8.8.4.4 2001:4860:4860::8844 2001:4860:4860::8888
regexp:^123456789 192.168.1.1
test.com 1.2.3.4 # will be replaced
test.com 2.3.4.5 
# nxdomain.com 1.2.3.4
`

func Test_hostsContainer_Match(t *testing.T) {
	m := domain.NewMixMatcher[*IPs]()
	m.SetDefaultMatcher(domain.MatcherDomain)
	err := domain.LoadFromTextReader[*IPs](m, bytes.NewBuffer([]byte(testHosts)), ParseIPs)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHosts(m)

	type args struct {
		name string
		typ  uint16
	}
	tests := []struct {
		name        string
		args        args
		wantMatched bool
		wantAddr    []string
	}{
		{"matched A", args{name: "dns.google.", typ: dns.TypeA}, true, []string{"8.8.8.8", "8.8.4.4"}},
		{"matched AAAA", args{name: "dns.google.", typ: dns.TypeAAAA}, true, []string{"2001:4860:4860::8844", "2001:4860:4860::8888"}},
		{"not matched A", args{name: "nxdomain.com.", typ: dns.TypeA}, false, nil},
		{"not matched A", args{name: "sub.dns.google.", typ: dns.TypeA}, false, nil},
		{"matched regexp A", args{name: "123456789.test.", typ: dns.TypeA}, true, []string{"192.168.1.1"}},
		{"not matched regexp A", args{name: "0123456789.test.", typ: dns.TypeA}, false, nil},
		{"test replacement", args{name: "test.com.", typ: dns.TypeA}, true, []string{"2.3.4.5"}},
		{"test matched domain with mismatched type", args{name: "test.com.", typ: dns.TypeAAAA}, true, nil},
	}
	for _, tt := range tests {
		q := dns.NewMsg(tt.args.name, tt.args.typ)

		t.Run(tt.name, func(t *testing.T) {
			r := h.LookupMsg(q)
			if tt.wantMatched && r == nil {
				t.Fatal("Lookup() should not return a nil result")
			}

			for _, s := range tt.wantAddr {
				wantIP, err := netip.ParseAddr(s)
				if err != nil {
					t.Fatal("invalid test case addr")
				}
				found := false
				for _, rr := range r.Answer {
					var ip netip.Addr
					switch rr := rr.(type) {
					case *dns.A:
						ip = rr.A.Addr
					case *dns.AAAA:
						ip = rr.AAAA.Addr
					default:
						continue
					}
					if ip == wantIP {
						found = true
						break
					}
				}
				if !found {
					t.Fatal("wanted ip is not found in response")
				}
			}
		})
	}
}
