// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"time"

	"tailscale.com/syncs"
)

// Prober periodically pings the network and checks for port-mapping services.
type Prober struct {
	// stop will stop the prober
	stop func()

	// Each of the SubResults below is intended to expose whether a specific service is available
	// for use on a client, and the most recent seen time. Should not be modified externally, and
	// will be periodically updated.

	// PMP stores the result of probing pmp services and is populated by the prober.
	PMP syncs.WaitableResult
	// PCP stores the result of probing pcp services and is populated by the prober.
	PCP syncs.WaitableResult
	// UPnP stores the result of probing pcp services and is populated by the prober.
	UPnP syncs.WaitableResult
}

// newProber will start a prober if it does not exist on the given portmapping client.
// Should be called when the client's lock is held.
func (c *Client) newProber(ctx context.Context) {
	stop := false
	p := &Prober{
		PMP:  syncs.NewWaitableResult(),
		PCP:  syncs.NewWaitableResult(),
		UPnP: syncs.NewWaitableResult(),
		stop: func() { stop = true },
	}
	c.prober = p
	go func() {
		for {
			res, err := c.oldProbe(ctx)
			p.PMP.Set(res.PMP, err)
			p.PCP.Set(res.PCP, err)
			p.UPnP.Set(res.UPnP, err)

			time.Sleep(trustServiceStillAvailableDuration * 3 / 4)
			if stop {
				return
			}
		}
	}()
}

// Stop gracefully turns the Prober off, completing the current probes before exiting.
//
// Calling stop Close multiple times will have no additional effects.
func (p *Prober) Close() { p.stop() }

// CurrentStatus returns the current results of the prober, regardless of whether they have
// completed or not.
func (p *Prober) Current() (ProbeResult, error) {
	var res ProbeResult
	_, hasPMP, errPMP := p.PMP.Current()
	res.PMP = hasPMP
	err := errPMP

	_, hasUPnP, errUPnP := p.UPnP.Current()
	res.UPnP = hasUPnP
	if err == nil {
		err = errUPnP
	}

	_, hasPCP, errPCP := p.PCP.Current()
	res.PCP = hasPCP
	if err == nil {
		err = errPCP
	}
	return res, err
}

// StatusBlock blocks the caller until probing all services has completed, regardless of success
// or failure. If there is an error on any probe, it will return one.
func (p *Prober) Complete() (ProbeResult, error) {
	var res ProbeResult
	hasPMP, errPMP := p.PMP.Complete()
	res.PMP = hasPMP
	err := errPMP

	hasUPnP, errUPnP := p.UPnP.Complete()
	res.UPnP = hasUPnP
	if err == nil {
		err = errUPnP
	}

	hasPCP, errPCP := p.PCP.Complete()
	res.PCP = hasPCP
	if err == nil {
		err = errPCP
	}
	return res, err
}
