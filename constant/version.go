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

package constant

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	e "gitlab.com/go-extension/http"
)

var Version = "undefined"

var BuildTime = "00.00.00"

func init() {
	if BuildTime == "00.00.00" {
		BuildTime = time.Now().Format("06.01.02")
	}
}

const DnsContentType = "application/dns-message"

type HttpHeader interface {
	Get(string) string
	Set(key, value string)
}

func MakeHeader[T *http.Request | *e.Request](req T) {
	var h HttpHeader

	switch r := any(req).(type) {
	case *http.Request:
		h = r.Header
	case *e.Request:
		h = r.Header
	}

	if h != nil {
		h.Set("Content-Type", DnsContentType)
		h.Set("Accept", DnsContentType)
		h.Set("User-Agent", "curl/8.0")
	}
}

func DealResponse[T *http.Response | *e.Response](res T) error {
	var h HttpHeader
	var code int
	var status string

	switch r := any(res).(type) {
	case *http.Response:
		h = r.Header
		code = r.StatusCode
		status = r.Status
	case *e.Response:
		h = r.Header
		code = r.StatusCode
		status = r.Status
	}

	if code != 200 {
		return fmt.Errorf("unexpected status %v: %s", code, status)
	}
	if contentType := h.Get("Content-Type"); contentType != DnsContentType {
		return fmt.Errorf("unexpected content type: %s", contentType)
	}
	if contentLength := h.Get("Content-Length"); contentLength != "" {
		if length, err := strconv.Atoi(contentLength); err == nil && length == 0 {
			return fmt.Errorf("empty response")
		}
	}
	return nil
}
