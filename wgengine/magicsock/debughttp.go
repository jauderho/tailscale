// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// ServeHTTPDebug serves an HTML representation of the innards of c for debugging.
//
// It's accessible either from tailscaled's debug port (at
// /debug/magicsock) or via peerapi to a peer that's owned by the same
// user (so they can e.g. inspect their phones).
func (c *Conn) ServeHTTPDebug(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<h1>magicsock</h1>")

	fmt.Fprintf(w, "<h2 id=derp><a href=#derp>#</a> DERP</h2><ul>")
	if c.derpMap != nil {
		type D struct {
			regionID   int
			lastWrite  time.Time
			createTime time.Time
		}
		ent := make([]D, 0, len(c.activeDerp))
		for rid, ad := range c.activeDerp {
			ent = append(ent, D{
				regionID:   rid,
				lastWrite:  *ad.lastWrite,
				createTime: ad.createTime,
			})
		}
		sort.Slice(ent, func(i, j int) bool {
			return ent[i].regionID < ent[j].regionID
		})
		for _, e := range ent {
			r, ok := c.derpMap.Regions[e.regionID]
			if !ok {
				continue
			}
			home := ""
			if e.regionID == c.myDerp {
				home = "🏠"
			}
			fmt.Fprintf(w, "<li>%s %d - %v: created %v ago, write %v ago</li>\n",
				home, e.regionID, html.EscapeString(r.RegionCode),
				now.Sub(e.createTime).Round(time.Second),
				now.Sub(e.lastWrite).Round(time.Second),
			)
		}

	}
	fmt.Fprintf(w, "</ul>\n")

	fmt.Fprintf(w, "<h2 id=ipport><a href=#ipport>#</a> ip:port to endpoint</h2><ul>")
	{
		type kv struct {
			ipp netaddr.IPPort
			pi  *peerInfo
		}
		ent := make([]kv, 0, len(c.peerMap.byIPPort))
		for k, v := range c.peerMap.byIPPort {
			ent = append(ent, kv{k, v})
		}
		sort.Slice(ent, func(i, j int) bool { return ipPortLess(ent[i].ipp, ent[j].ipp) })
		for _, e := range ent {
			ep := e.pi.ep
			shortStr := ep.publicKey.ShortString()
			fmt.Fprintf(w, "<li>%v: <a href='#%v'>%v</a></li>\n", e.ipp, strings.Trim(shortStr, "[]"), shortStr)
		}

	}
	fmt.Fprintf(w, "</ul>\n")

	fmt.Fprintf(w, "<h2 id=bykey><a href=#bykey>#</a> endpoints by key</h2>")
	{
		type kv struct {
			pub key.NodePublic
			pi  *peerInfo
		}
		ent := make([]kv, 0, len(c.peerMap.byNodeKey))
		for k, v := range c.peerMap.byNodeKey {
			ent = append(ent, kv{k, v})
		}
		sort.Slice(ent, func(i, j int) bool { return ent[i].pub.Less(ent[j].pub) })

		peers := map[key.NodePublic]*tailcfg.Node{}
		if c.netMap != nil {
			for _, p := range c.netMap.Peers {
				peers[p.Key] = p
			}
		}

		for _, e := range ent {
			ep := e.pi.ep
			shortStr := e.pub.ShortString()
			name := peerDebugName(peers[e.pub])
			fmt.Fprintf(w, "<h3 id=%v><a href='#%v'>%v</a> - %s</h3>\n",
				strings.Trim(shortStr, "[]"),
				strings.Trim(shortStr, "[]"),
				shortStr,
				html.EscapeString(name))
			printEndpointHTML(w, ep)
		}

	}
}

func printEndpointHTML(w io.Writer, ep *endpoint) {
	lastRecv := ep.lastRecv.LoadAtomic()

	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.lastSend == 0 && lastRecv == 0 {
		return // no activity ever
	}

	now := time.Now()
	mnow := mono.Now()
	fmtMono := func(m mono.Time) string {
		if m == 0 {
			return "-"
		}
		return mnow.Sub(m).Round(time.Millisecond).String()
	}

	fmt.Fprintf(w, "<p>Best: <b>%+v</b>, %v ago (for %v)</p>\n", ep.bestAddr, fmtMono(ep.bestAddrAt), ep.trustBestAddrUntil.Sub(mnow).Round(time.Millisecond))
	fmt.Fprintf(w, "<p>heartbeating: %v</p>\n", ep.heartBeatTimer != nil)
	fmt.Fprintf(w, "<p>lastSend: %v ago</p>\n", fmtMono(ep.lastSend))
	fmt.Fprintf(w, "<p>lastFullPing: %v ago</p>\n", fmtMono(ep.lastFullPing))

	eps := make([]netaddr.IPPort, 0, len(ep.endpointState))
	for ipp := range ep.endpointState {
		eps = append(eps, ipp)
	}
	sort.Slice(eps, func(i, j int) bool { return ipPortLess(eps[i], eps[j]) })
	io.WriteString(w, "<p>Endpoints:</p><ul>")
	for _, ipp := range eps {
		s := ep.endpointState[ipp]
		if ipp == ep.bestAddr.IPPort {
			fmt.Fprintf(w, "<li><b>%s</b>: (best)<ul>", ipp)
		} else {
			fmt.Fprintf(w, "<li>%s: ...<ul>", ipp)
		}
		fmt.Fprintf(w, "<li>lastPing: %v ago</li>\n", fmtMono(s.lastPing))
		if s.lastGotPing.IsZero() {
			fmt.Fprintf(w, "<li>disco-learned-at: -</li>\n")
		} else {
			fmt.Fprintf(w, "<li>disco-learned-at: %v ago</li>\n", now.Sub(s.lastGotPing).Round(time.Second))
		}
		fmt.Fprintf(w, "<li>callMeMaybeTime: %v</li>\n", s.callMeMaybeTime)
		for i := range s.recentPongs {
			if i == 5 {
				break
			}
			pos := (int(s.recentPong) - i) % len(s.recentPongs)
			pr := s.recentPongs[pos]
			fmt.Fprintf(w, "<li>pong %v ago: in %v, from %v src %v</li>\n",
				fmtMono(pr.pongAt), pr.latency.Round(time.Millisecond/10),
				pr.from, pr.pongSrc)
		}
		fmt.Fprintf(w, "</ul></li>\n")
	}
	io.WriteString(w, "</ul>")

}

func peerDebugName(p *tailcfg.Node) string {
	if p == nil {
		return ""
	}
	n := p.Name
	if i := strings.Index(n, "."); i != -1 {
		return n[:i]
	}
	return p.Hostinfo.Hostname()
}

func ipPortLess(a, b netaddr.IPPort) bool {
	if v := a.IP().Compare(b.IP()); v != 0 {
		return v < 0
	}
	return a.Port() < b.Port()
}
