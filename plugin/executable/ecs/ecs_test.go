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

package ecs

import (
	"context"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
)

func Test_ecsPlugin(t *testing.T) {
	tests := []struct {
		name       string
		args       Args
		qtype      uint16
		qHasEDNS0  bool
		qHasECS    string
		clientAddr string
		wantAddr   string
		rWantEDNS0 bool
		rWantECS   bool
	}{
		{"edns0 contingency", Args{Auto: true}, dns.TypeA, false, "", "1.0.0.0", "1.0.0.0", false, false},
		{"edns0 contingency2", Args{Auto: true}, dns.TypeA, true, "", "1.0.0.0", "1.0.0.0", true, false},
		{"ecs contingency", Args{Auto: true}, dns.TypeA, true, "", "1.0.0.0", "1.0.0.0", true, false},
		{"ecs contingency2", Args{Auto: true}, dns.TypeA, true, "1.0.0.0", "1.0.0.0", "1.0.0.0", true, true},

		{"auto", Args{Auto: true}, dns.TypeA, false, "", "1.0.0.0", "1.0.0.0", false, false},
		{"auto2", Args{Auto: true}, dns.TypeA, false, "", "", "", false, false},

		{"overwrite off", Args{Auto: true}, dns.TypeA, true, "1.2.3.4", "1.0.0.0", "1.2.3.4", true, true},
		{"overwrite on", Args{Auto: true, ForceOverwrite: true}, dns.TypeA, true, "1.2.3.4", "1.0.0.0", "1.0.0.0", true, true},

		{"preset v4", Args{IPv4: "1.2.3.4"}, dns.TypeA, false, "", "", "1.2.3.4", false, false},
		{"preset v6", Args{IPv6: "::1"}, dns.TypeA, false, "", "", "::1", false, false},
		{"preset both", Args{IPv4: "1.2.3.4", IPv6: "::1"}, dns.TypeA, false, "", "", "1.2.3.4", false, false},
		{"preset both2", Args{IPv4: "1.2.3.4", IPv6: "::1"}, dns.TypeAAAA, false, "", "", "::1", false, false},
	}
	for _, tt := range tests {
		p, err := newPlugin(coremain.NewBP("ecs", PluginType, nil, nil), &tt.args)
		if err != nil {
			t.Fatal(err)
		}

		t.Run(tt.name, func(t *testing.T) {
			q := dns.NewMsg(".", tt.qtype)
			r := new(dns.Msg)
			dnsutil.SetReply(r, q)

			if tt.qHasEDNS0 {
				dnsutils.UpgradeEDNS0(q)
				dnsutils.UpgradeEDNS0(r)

				if len(tt.qHasECS) > 0 {
					ip, err := netip.ParseAddr(tt.qHasECS)
					if err != nil {
						t.Fatal(err)
					}
					dnsutils.AddECS(q, dnsutils.NewEDNS0Subnet(netip.IPv6Loopback(), 24, false), true)
					dnsutils.AddECS(q, dnsutils.NewEDNS0Subnet(ip, 24, false), true)
				}
			}

			var ip netip.Addr
			if len(tt.clientAddr) > 0 {
				ip, err = netip.ParseAddr(tt.clientAddr)
				if err != nil {
					t.Fatal(err)
				}
			}
			meta := C.NewRequestMeta(ip)
			qCtx := C.NewContext(q, meta)

			next := executable_seq.WrapExecutable(&executable_seq.DummyExecutable{
				WantR: r,
			})
			if err := p.Exec(context.Background(), qCtx, next); err != nil {
				t.Fatal(err)
			}

			var qECS netip.Addr
			e := dnsutils.GetECS(q)
			if e != nil {
				qECS = e.Address
			}
			wantAddr, _ := netip.ParseAddr(tt.wantAddr)
			if qECS != wantAddr {
				t.Fatalf("want addr %v, got %v", tt.wantAddr, qECS)
			}

			if res := dnsutils.GetECS(qCtx.R()) != nil; res != tt.rWantECS {
				t.Fatalf("want rWantECS %v, got %v", tt.rWantECS, res)
			}
			if res := qCtx.R().IsEdns0(); res != tt.rWantEDNS0 {
				t.Fatalf("want rWantEDNS0 %v, got %v", tt.rWantEDNS0, res)
			}
		})
	}
}
