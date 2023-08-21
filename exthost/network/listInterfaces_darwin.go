// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package network

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"net"
)

func ListInterfaces(_ context.Context) ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get interfaces")
		return nil, fmt.Errorf("could not list interfaces: %w", err)
	}

	var interfaces []Interface
	for _, iface := range ifaces {
		var flags []string
		if iface.Flags&net.FlagUp != 0 {
			flags = append(flags, "UP")
		}
		if iface.Flags&net.FlagBroadcast != 0 {
			flags = append(flags, "BROADCAST")
		}
		if iface.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "LOOPBACK")
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			flags = append(flags, "POINTTOPOINT")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			flags = append(flags, "MULTICAST")
		}
		interfaces = append(interfaces, Interface{
			Index:    uint(iface.Index),
			Name:     iface.Name,
			LinkType: iface.HardwareAddr.String(),
			Flags:    flags,
		})
	}
	return interfaces, nil
}
