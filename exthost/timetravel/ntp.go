package timetravel

import (
	"context"
	"github.com/steadybit/action-kit/go/action_kit_commons/network"
	"github.com/steadybit/action-kit/go/action_kit_commons/runc"
)

func AdjustNtpTrafficRules(ctx context.Context, r runc.Runc, allowNtpTraffic bool) error {
	initProcess, err := runc.ReadLinuxProcessInfo(ctx, 1)
	if err != nil {
		return err
	}

	sidecar := network.SidecarOpts{
		TargetProcess: initProcess,
		IdSuffix:      "host",
		ImagePath:     "/",
	}

	opts := &network.BlackholeOpts{
		IpProto: network.IpProtoUdp,
		Filter: network.Filter{
			Include: network.NewNetWithPortRanges(network.NetAny, network.PortRange{From: 123, To: 123}),
		},
	}

	if allowNtpTraffic {
		return network.Revert(ctx, r, sidecar, opts)
	} else {
		return network.Apply(ctx, r, sidecar, opts)
	}
}
