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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/bundled_upstream"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/upstream"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

const PluginType = "fast_forward"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*fastForward)(nil)

type fastForward struct {
	*coremain.BP
	args *Args

	upstreamWrappers []bundled_upstream.Upstream
	upstreamsCloser  []io.Closer
}

type Args struct {
	Upstream []*UpstreamConfig `yaml:"upstream"`
	CA       []string          `yaml:"ca"`
}

type UpstreamConfig struct {
	Addr           string   `yaml:"addr"` // required
	DialAdders     []string `yaml:"dial_addr"`
	Trusted        bool     `yaml:"trusted"`
	Socks5         string   `yaml:"socks5"`
	S5Username     string   `yaml:"s5_username"`
	S5Password     string   `yaml:"s5_password"`
	SoMark         int      `yaml:"so_mark"`
	BindToDevice   string   `yaml:"bind_to_device"`
	IdleTimeout    int      `yaml:"idle_timeout"`
	MaxConns       int      `yaml:"max_conns"`
	EnablePipeline bool     `yaml:"enable_pipeline"`
	Bootstrap      string   `yaml:"bootstrap"`
	Insecure       bool     `yaml:"insecure"`
	KernelTX       bool     `yaml:"kernel_tx"` // use kernel tls to send data
	KernelRX       bool     `yaml:"kernel_rx"` // use kernel tls to receive data
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newFastForward(bp, args.(*Args))
}

func newFastForward(bp *coremain.BP, args *Args) (*fastForward, error) {
	if len(args.Upstream) == 0 {
		return nil, errors.New("no upstream is configured")
	}

	f := &fastForward{
		BP:   bp,
		args: args,
	}

	// rootCAs
	var rootCAs *x509.CertPool
	if len(args.CA) != 0 {
		var err error
		rootCAs, err = utils.LoadCertPool(args.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca: %w", err)
		}
	}

	for i, c := range args.Upstream {
		if len(c.Addr) == 0 {
			return nil, errors.New("missing server addr")
		}

		trusted := c.Trusted || i == 0 // Set first upstream as trusted upstream.
		if strings.HasPrefix(c.Addr, "udpme://") {
			u := newUDPME(c.Addr[8:], trusted)
			f.upstreamWrappers = append(f.upstreamWrappers, u)
		} else {
			u, addr, err := newUpstream(bp, c, rootCAs)
			if err != nil {
				bp.L().Warn("Upstream init failed", zap.String("addr", c.Addr), zap.Error(err))
				continue
			}

			w := &upstreamWrapper{
				address: c.Addr,
				ipAddr:  addr,
				trusted: trusted,
				u:       u,
			}

			f.upstreamWrappers = append(f.upstreamWrappers, w)
			f.upstreamsCloser = append(f.upstreamsCloser, u)
		}
	}
	return f, nil
}

func newUpstream(bp *coremain.BP, c *UpstreamConfig, ca *x509.CertPool) (upstream.Upstream, string, error) {
	dialAdders := c.DialAdders
	if len(dialAdders) == 0 {
		dialAdders = append(dialAdders, "")
	}
	upstreams := make([]upstream.Upstream, 0, len(dialAdders))

	for _, addr := range dialAdders {
		opt := &upstream.Opt{
			DialAddr:       addr,
			Socks5:         c.Socks5,
			S5Username:     c.S5Username,
			S5Password:     c.S5Password,
			SoMark:         c.SoMark,
			BindToDevice:   c.BindToDevice,
			IdleTimeout:    time.Duration(c.IdleTimeout) * time.Second,
			MaxConns:       c.MaxConns,
			EnablePipeline: c.EnablePipeline,
			Bootstrap:      c.Bootstrap,
			Insecure:       c.Insecure,
			RootCAs:        ca,
			KernelTX:       c.KernelTX,
			KernelRX:       c.KernelRX,
			Logger:         bp.L(),
		}

		u, err := upstream.NewUpstream(c.Addr, opt)
		if err != nil {
			return nil, "", fmt.Errorf("failed to init upstream: %w", err)
		}
		upstreams = append(upstreams, u)
	}
	k, err := SelectFastestUpstream(upstreams)
	if err != nil {
		k = 0
		err = fmt.Errorf("failed to set upstream, because: %w", err)
		bp.L().Error("upstream", zap.String("addr", c.Addr), zap.Error(err))
	}
	return upstreams[k], dialAdders[k], nil
}

func SelectFastestUpstream(upstreams []upstream.Upstream) (int, error) {
	if len(upstreams) == 1 {
		return 0, nil
	}

	var wg sync.WaitGroup
	ch := make(chan int, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	for i, u := range upstreams {
		wg.Add(1)
		go func() {
			defer wg.Done()

			q := dns.NewMsg("example.com.", dns.TypeA)
			r, err := u.ExchangeContext(ctx, q)
			if err != nil || r == nil || r.ID != q.ID {
				return
			}

			select {
			case ch <- i:
			case <-ctx.Done():
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	select {
	case i := <-ch:
		return i, nil
	case <-ctx.Done():
		return -1, errors.New("all upstream timeouts")
	}
}

type upstreamWrapper struct {
	address string
	ipAddr  string
	trusted bool
	u       upstream.Upstream
}

func (u *upstreamWrapper) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	return u.u.ExchangeContext(ctx, q)
}

func (u *upstreamWrapper) Address() string {
	return u.address
}

func (u *upstreamWrapper) IPAddress() string {
	return u.ipAddr
}

func (u *upstreamWrapper) Trusted() bool {
	return u.trusted
}

// Exec forwards qCtx.Q() to upstreams, and sets qCtx.R().
// qCtx.Status() will be set as
// - handler.ContextStatusResponded: if it received a response.
// - handler.ContextStatusServerFailed: if all upstreams failed.
func (f *fastForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecChainNode) error {
	qCtx.SetStatus(f.exec(ctx, qCtx))
	return executable_seq.ExecChain(ctx, qCtx, next)
}

func (f *fastForward) exec(ctx context.Context, qCtx *query_context.Context) (err error) {
	var r *dns.Msg
	var addr string

	deadline := time.Now().Add(time.Second * 3)
	if ddl, ok := ctx.Deadline(); !ok || ddl.After(deadline) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	r, err, addr = bundled_upstream.ExchangeParallel(ctx, qCtx, f.upstreamWrappers, f.L())

	if r != nil {
		qCtx.SetResponse(r)
		qCtx.SetFrom(f.Tag() + "@" + addr)
	}
	return err
}

func (f *fastForward) Shutdown() error {
	for _, u := range f.upstreamsCloser {
		u.Close()
	}
	return nil
}
