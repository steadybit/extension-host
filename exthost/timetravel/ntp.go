// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Steadybit GmbH

package timetravel

import (
	"context"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
)

func AdjustNtpTrafficRules(ctx context.Context, runner netfault.CommandRunner, allowNtpTraffic bool) error {
	opts := &netfault.BlackholeOpts{
		IpProto: netfault.IpProtoUdp,
		Filter: netfault.Filter{
			Include: network.NewNetWithPortRanges(network.NetAny, network.PortRange{From: 123, To: 123}),
		},
	}

	if allowNtpTraffic {
		return netfault.Revert(ctx, runner, opts)
	} else {
		return netfault.Apply(ctx, runner, opts)
	}
}
