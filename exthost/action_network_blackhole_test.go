// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"github.com/steadybit/extension-host/config"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_localhostExcludesForOwnPorts(t *testing.T) {
	config.Config.Port = 8085
	config.Config.HealthPort = 8081

	var got []string
	for _, nwp := range localhostExcludesForOwnPorts() {
		got = append(got, nwp.String())
	}

	assert.ElementsMatch(t, []string{
		"127.0.0.0/8 8085 # ext. port (localhost)",
		"127.0.0.0/8 8081 # ext. port (localhost)",
		"::1/128 8085 # ext. port (localhost)",
		"::1/128 8081 # ext. port (localhost)",
	}, got)
}
