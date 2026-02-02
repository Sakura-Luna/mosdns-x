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
)

// PadToMinimum pads m to the minimum length.
// If the length of m is larger than minLen, PadToMinimum won't do anything.
// upgraded indicates the m was upgraded to an EDNS0 msg.
// newPadding indicates the Padding option is new to m.
func PadToMinimum(m *dns.Msg, minLen int) (upgraded, newPadding bool) {
	err := m.Pack()
	l := len(m.Data)
	if err != nil || l >= minLen {
		return false, false
	}

	paddingLen := 0
	edns0 := m.IsEdns0()
	if edns0 {
		if pad := GetEDNS0Option(m, dns.CodePADDING); pad != nil { // q is padded.
			paddingLen = minLen - (l - pad.Len() + 4)
			RemoveEDNS0Option(m, dns.CodePADDING)
		} else {
			paddingLen = minLen - l - 4 // a Padding option has a 4 bytes header.
			newPadding = true
		}
	} else {
		paddingLen = minLen - l - 15 // 4 bytes padding header + 11 bytes EDNS0 header.
		upgraded, newPadding = true, true
	}

	if paddingLen < 0 {
		return false, false
	}
	m.Pseudo = append(m.Pseudo, dnsutil.MakePadding(paddingLen))
	return upgraded, newPadding
}
