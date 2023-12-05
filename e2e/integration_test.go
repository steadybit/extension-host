// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/diskfill"
	"github.com/steadybit/action-kit/go/action_kit_test/e2e"
	"github.com/steadybit/discovery-kit/go/discovery_kit_api"
	"github.com/steadybit/discovery-kit/go/discovery_kit_test/validate"
	"github.com/steadybit/extension-host/exthost"
	"github.com/steadybit/extension-kit/extutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	executionContext = &action_kit_api.ExecutionContext{
		AgentAwsAccountId: nil,
		RestrictedEndpoints: extutil.Ptr([]action_kit_api.RestrictedEndpoint{
			{
				Name:    "minikube ssh",
				Url:     "",
				Cidr:    "0.0.0.0/0",
				PortMin: 22,
				PortMax: 22,
			},
			{
				Name:    "minikube ssh",
				Url:     "",
				Cidr:    "::/0",
				PortMin: 22,
				PortMax: 22,
			},
			{
				Name:    "minikube k8s api",
				Url:     "",
				Cidr:    "0.0.0.0/0",
				PortMin: 8443,
				PortMax: 8443,
			},
			{
				Name:    "minikube k8s api",
				Url:     "",
				Cidr:    "::/0",
				PortMin: 8443,
				PortMax: 8443,
			},
		}),
	}
)

func getTarget(m *e2e.Minikube) *action_kit_api.Target {
	return &action_kit_api.Target{
		Attributes: map[string][]string{
			"host.hostname": {m.Profile},
		},
	}
}

func TestWithMinikube(t *testing.T) {
	extFactory := e2e.HelmExtensionFactory{
		Name: "extension-host",
		Port: 8085,
		ExtraArgs: func(m *e2e.Minikube) []string {
			return []string{
				"--set", fmt.Sprintf("container.runtime=%s", m.Runtime),
				"--set", "discovery.attributes.excludes.host={host.nic}",
				"--set", "logging.level=debug",
			}
		},
	}

	e2e.WithMinikube(t, getMinikubeOptions(), &extFactory, []e2e.WithMinikubeTestCase{
		{
			Name: "validate discovery",
			Test: validateDiscovery,
		},
		{
			Name: "target discovery",
			Test: testDiscovery,
		},
		{
			Name: "stress cpu",
			Test: testStressCpu,
		},
		{
			Name: "stress memory",
			Test: testStressMemory,
		}, {
			Name: "stress io",
			Test: testStressIo,
		},
		{
			Name: "time travel",
			Test: testTimeTravel,
		},
		{
			Name: "stop process",
			Test: testStopProcess,
		},
		{
			Name: "network delay",
			Test: testNetworkDelay,
		},
		{
			Name: "network blackhole",
			Test: testNetworkBlackhole,
		},
		{
			Name: "network block dns",
			Test: testNetworkBlockDns,
		},
		{
			Name: "network limit bandwidth",
			Test: testNetworkLimitBandwidth,
		},
		{
			Name: "network package loss",
			Test: testNetworkPackageLoss,
		},
		{
			Name: "network package corruption",
			Test: testNetworkPackageCorruption,
		},
		{
			Name: "fill disk",
			Test: testFillDisk,
		},
		{
			Name: "shutdown host",
			Test: testShutdownHost, // if you run this test locally, you will need to restart your docker machine
		},
	})
}

func testStressCpu(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testStressCpu")
	config := struct {
		Duration int `json:"duration"`
		CpuLoad  int `json:"cpuLoad"`
		Workers  int `json:"workers"`
	}{Duration: 50000, Workers: 0, CpuLoad: 50}
	exec, err := e.RunAction("com.steadybit.extension_host.stress-cpu", getTarget(m), config, nil)
	require.NoError(t, err)

	e2e.AssertProcessRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "stress-ng", true)
	require.NoError(t, exec.Cancel())
	requireAllSidecarsCleanedUp(t, m, e)
}

func testStressMemory(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testStressMemory")
	config := struct {
		Duration   int `json:"duration"`
		Percentage int `json:"percentage"`
	}{Duration: 50000, Percentage: 50}

	exec, err := e.RunAction("com.steadybit.extension_host.stress-mem", getTarget(m), config, nil)
	require.NoError(t, err)
	e2e.AssertProcessRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "stress-ng", true)
	require.NoError(t, exec.Cancel())
}

func testStressIo(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	err := m.SshExec("sudo", "mkdir", "-p", "/stressng").Run()
	require.NoError(t, err)

	for _, mode := range []string{"read_write_and_flush", "read_write", "flush"} {
		t.Run(mode, func(t *testing.T) {
			config := struct {
				Duration        int    `json:"duration"`
				Path            string `json:"path"`
				MbytesPerWorker int    `json:"mbytes_per_worker"`
				Workers         int    `json:"workers"`
				Mode            string `json:"mode"`
			}{Duration: 20000, Workers: 1, MbytesPerWorker: 50, Path: "/stressng", Mode: mode}

			action, err := e.RunAction("com.steadybit.extension_host.stress-io", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			e2e.AssertProcessRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "stress-ng", true)
			require.NoError(t, action.Cancel())
			e2e.AssertProcessNOTRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "stress-ng")

			out, err := runInMinikube(m, "ls", "/stressng")
			require.NoError(t, err)
			require.Empty(t, strings.TrimSpace(string(out)), "no stress-ng directories must be present")
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testTimeTravel(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testTimeTravel")
	config := struct {
		Duration   int  `json:"duration"`
		Offset     int  `json:"offset"`
		DisableNtp bool `json:"disableNtp"`
	}{
		Duration:   30000,
		Offset:     int((360 * time.Second).Milliseconds()),
		DisableNtp: true,
	}

	action, err := e.RunAction("com.steadybit.extension_host.timetravel", getTarget(m), config, nil)
	defer func() { _ = action.Cancel() }()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		diff := getTimeDiffBetweenNowAndContainerTime(t, m, e)
		assert.InDelta(t, config.Offset, diff.Milliseconds(), 2000)
	}, 10*time.Second, 1*time.Second, "time travel failed to apply offset")

	// rollback
	require.NoError(t, action.Cancel())
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		diff := getTimeDiffBetweenNowAndContainerTime(t, m, e)
		assert.InDelta(t, 0, diff.Milliseconds(), 2000)
	}, 10*time.Second, 1*time.Second, "time travel failed to rollback offset")
}

func getTimeDiffBetweenNowAndContainerTime(t *testing.T, m *e2e.Minikube, e *e2e.Extension) time.Duration {
	out, err := m.PodExec(e.Pod, "steadybit-extension-host", "date", "+%s")
	if err != nil {
		t.Fatal(err)
		return 0
	}
	containerSecondsSinceEpoch := extutil.ToInt64(strings.TrimSpace(out))
	if containerSecondsSinceEpoch == 0 {
		t.Fatal("could not parse container time")
		return 0
	}
	containerTime := time.Unix(containerSecondsSinceEpoch, 0)
	return time.Until(containerTime)
}

func validateDiscovery(t *testing.T, _ *e2e.Minikube, e *e2e.Extension) {
	assert.NoError(t, validate.ValidateEndpointReferences("/", e.Client))
}

func testDiscovery(t *testing.T, _ *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testDiscovery")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	target, err := e2e.PollForTarget(ctx, e, "com.steadybit.extension_host.host", func(target discovery_kit_api.Target) bool {
		log.Debug().Msgf("targetHost: %v", target.Attributes["host.hostname"])
		return e2e.HasAttribute(target, "host.hostname", "e2e-docker")
	})

	require.NoError(t, err)
	assert.Equal(t, target.TargetType, "com.steadybit.extension_host.host")
	assert.NotContains(t, target.Attributes, "host.nic")
}

func testStopProcess(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testStopProcess")
	config := struct {
		Duration int    `json:"duration"`
		Graceful bool   `json:"graceful"`
		Process  string `json:"process"`
		Delay    int    `json:"delay"`
	}{Duration: 10000, Graceful: true, Process: "tail", Delay: 1}

	e2e.AssertProcessNOTRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "tail")
	go func() {
		_, _ = m.PodExec(e.Pod, "steadybit-extension-host", "tail", "-f", "/dev/null")
	}()

	e2e.AssertProcessRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "tail", true)

	exec, err := e.RunAction("com.steadybit.extension_host.stop-process", getTarget(m), config, nil)
	require.NoError(t, err)
	e2e.AssertProcessNOTRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "tail")
	require.NoError(t, exec.Cancel())
}
func testShutdownHost(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	t.Skip("Deactivated cause otherwise the shutdown will prevent the coverage collection from the tests above must be the last test, because it will shutdown the minikube host (minikube cannot be restarted")

	log.Info().Msg("Starting testShutdownHost")
	config := struct {
		Reboot bool `json:"reboot"`
	}{Reboot: true}

	_, err := e.RunAction("com.steadybit.extension_host.shutdown", getTarget(m), config, nil)
	require.NoError(t, err)
	e2e.Retry(t, 5, 1*time.Second, func(r *e2e.R) {
		_, err = m.PodExec(e.Pod, "steadybit-extension-host", "tail", "-f", "/dev/null")
		if err == nil {
			r.Failed = true
			_, _ = fmt.Fprintf(r.Log, "expected error but got none")
		} else {
			log.Debug().Msgf("err: %v", err)
		}
	})
	assert.Error(t, err)
}

func testNetworkBlackhole(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testNetworkBlackhole")
	nginx := e2e.Nginx{Minikube: m}
	err := nginx.Deploy("nginx-network-blackhole")
	require.NoError(t, err, "failed to create pod")
	defer func() { _ = nginx.Delete() }()

	tests := []struct {
		name             string
		ip               []string
		hostname         []string
		port             []string
		WantedReachable  bool
		WantedReachesUrl bool
	}{
		{
			name:             "should blackhole all traffic",
			WantedReachable:  false,
			WantedReachesUrl: false,
		},
		{
			name:             "should blackhole only port 8080 traffic",
			port:             []string{"8080"},
			WantedReachable:  true,
			WantedReachesUrl: true,
		},
		{
			name:             "should blackhole only port 80, 443 traffic",
			port:             []string{"80", "443"},
			WantedReachable:  false,
			WantedReachesUrl: false,
		},
		{
			name:             "should blackhole only traffic for steadybit.com",
			hostname:         []string{"steadybit.com"},
			WantedReachable:  true,
			WantedReachesUrl: false,
		},
	}

	for _, tt := range tests {
		config := struct {
			Duration int      `json:"duration"`
			Ip       []string `json:"ip"`
			Hostname []string `json:"hostname"`
			Port     []string `json:"port"`
		}{
			Duration: 30000,
			Ip:       tt.ip,
			Hostname: tt.hostname,
			Port:     tt.port,
		}

		t.Run(tt.name, func(t *testing.T) {
			nginx.AssertIsReachable(t, true)
			nginx.AssertCanReach(t, "https://steadybit.com", true)

			action, err := e.RunAction(exthost.BaseActionID+".network_blackhole", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			nginx.AssertIsReachable(t, tt.WantedReachable)
			nginx.AssertCanReach(t, "https://steadybit.com", tt.WantedReachesUrl)

			require.NoError(t, action.Cancel())
			nginx.AssertIsReachable(t, true)
			nginx.AssertCanReach(t, "https://steadybit.com", true)
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testNetworkDelay(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testNetworkDelay")
	netperf := e2e.Netperf{Minikube: m}
	err := netperf.Deploy("delay")
	defer func() { _ = netperf.Delete() }()
	require.NoError(t, err)

	tests := []struct {
		name        string
		ip          []string
		hostname    []string
		port        []string
		interfaces  []string
		WantedDelay bool
	}{
		{
			name:        "should delay all traffic",
			WantedDelay: true,
		},
		{
			name:        "should delay only port 5000 traffic",
			port:        []string{"5000"},
			WantedDelay: true,
		},
		{
			name:        "should delay only port 80 traffic",
			port:        []string{"80"},
			WantedDelay: false,
		},
		{
			name:        "should delay only traffic for netperf",
			ip:          []string{netperf.ServerIp},
			WantedDelay: true,
		},
	}

	unaffectedLatency, err := netperf.MeasureLatency()
	require.NoError(t, err)

	for _, tt := range tests {
		config := struct {
			Duration     int      `json:"duration"`
			Delay        int      `json:"networkDelay"`
			Jitter       bool     `json:"networkDelayJitter"`
			Ip           []string `json:"ip"`
			Hostname     []string `json:"hostname"`
			Port         []string `json:"port"`
			NetInterface []string `json:"networkInterface"`
		}{
			Duration:     10000,
			Delay:        200,
			Jitter:       false,
			Ip:           tt.ip,
			Hostname:     tt.hostname,
			Port:         tt.port,
			NetInterface: tt.interfaces,
		}

		t.Run(tt.name, func(t *testing.T) {
			action, err := e.RunAction(exthost.BaseActionID+".network_delay", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			if tt.WantedDelay {
				netperf.AssertLatency(t, unaffectedLatency+time.Duration(config.Delay)*time.Millisecond*90/100, unaffectedLatency+time.Duration(config.Delay)*time.Millisecond*350/100)
			} else {
				netperf.AssertLatency(t, 0, unaffectedLatency*110/100)
			}
			require.NoError(t, action.Cancel())

			netperf.AssertLatency(t, 0, unaffectedLatency*110/100)
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testNetworkPackageLoss(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testNetworkPackageLoss")
	iperf := e2e.Iperf{Minikube: m}
	err := iperf.Deploy("loss")
	defer func() { _ = iperf.Delete() }()
	require.NoError(t, err)
	tests := []struct {
		name       string
		ip         []string
		hostname   []string
		port       []string
		interfaces []string
		WantedLoss bool
	}{
		{
			name:       "should loose packages on all traffic",
			WantedLoss: true,
		},
		{
			name:       "should loose packages only on port 5001 traffic",
			port:       []string{"5001"},
			WantedLoss: true,
		},
		{
			name:       "should loose packages only on port 80 traffic",
			port:       []string{"80"},
			WantedLoss: false,
		},
		{
			name:       "should loose packages only traffic for iperf server",
			ip:         []string{iperf.ServerIp},
			WantedLoss: true,
		},
	}

	for _, tt := range tests {
		config := struct {
			Duration     int      `json:"duration"`
			Percentage   int      `json:"percentage"`
			Ip           []string `json:"ip"`
			Hostname     []string `json:"hostname"`
			Port         []string `json:"port"`
			NetInterface []string `json:"networkInterface"`
		}{
			Duration:     20000,
			Percentage:   10,
			Ip:           tt.ip,
			Hostname:     tt.hostname,
			Port:         tt.port,
			NetInterface: tt.interfaces,
		}

		t.Run(tt.name, func(t *testing.T) {
			action, err := e.RunAction(exthost.BaseActionID+".network_package_loss", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			if tt.WantedLoss {
				iperf.AssertPackageLoss(t, float64(config.Percentage)*0.7, float64(config.Percentage)*1.3)
			} else {
				iperf.AssertPackageLoss(t, 0, 5)
			}
			require.NoError(t, action.Cancel())

			iperf.AssertPackageLoss(t, 0, 5)
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testNetworkPackageCorruption(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testNetworkPackageCorruption")
	iperf := e2e.Iperf{Minikube: m}
	err := iperf.Deploy("corruption")
	defer func() { _ = iperf.Delete() }()
	require.NoError(t, err)

	tests := []struct {
		name             string
		ip               []string
		hostname         []string
		port             []string
		interfaces       []string
		WantedCorruption bool
	}{
		{
			name:             "should corrupt packages on all traffic",
			WantedCorruption: true,
		},
		{
			name:             "should corrupt packages only on port 5001 traffic",
			port:             []string{"5001"},
			WantedCorruption: true,
		},
		{
			name:             "should corrupt packages only on port 80 traffic",
			port:             []string{"80"},
			WantedCorruption: false,
		},
		{
			name:             "should corrupt packages only traffic for iperf server",
			ip:               []string{iperf.ServerIp},
			WantedCorruption: true,
		},
	}

	for _, tt := range tests {
		config := struct {
			Duration     int      `json:"duration"`
			Corruption   int      `json:"networkCorruption"`
			Ip           []string `json:"ip"`
			Hostname     []string `json:"hostname"`
			Port         []string `json:"port"`
			NetInterface []string `json:"networkInterface"`
		}{
			Duration:     20000,
			Corruption:   10,
			Ip:           tt.ip,
			Hostname:     tt.hostname,
			Port:         tt.port,
			NetInterface: tt.interfaces,
		}

		t.Run(tt.name, func(t *testing.T) {
			e2e.Retry(t, 3, 1*time.Second, func(r *e2e.R) {
				action, err := e.RunAction(exthost.BaseActionID+".network_package_corruption", getTarget(m), config, executionContext)
				defer func() { _ = action.Cancel() }()
				if err != nil {
					r.Failed = true
				}

				if tt.WantedCorruption {
					packageLossResult := iperf.AssertPackageLossWithRetry(float64(config.Corruption)*0.7, float64(config.Corruption)*1.3, 8)
					if !packageLossResult {
						r.Failed = true
					}
				} else {
					packageLossResult := iperf.AssertPackageLossWithRetry(0, 5, 8)
					if !packageLossResult {
						r.Failed = true
					}
				}
				require.NoError(t, action.Cancel())

				packageLossResult := iperf.AssertPackageLossWithRetry(0, 5, 8)
				if !packageLossResult {
					r.Failed = true
				}
			})
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testNetworkLimitBandwidth(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	t.Skip("Skipping testNetworkLimitBandwidth because it does not work on minikube, but was tested manually on a real cluster")
	log.Info().Msg("Starting testNetworkLimitBandwidth")
	iperf := e2e.Iperf{Minikube: m}
	err := iperf.Deploy("bandwidth")
	defer func() { _ = iperf.Delete() }()
	require.NoError(t, err)

	tests := []struct {
		name        string
		ip          []string
		hostname    []string
		port        []string
		interfaces  []string
		WantedLimit bool
	}{
		{
			name:        "should limit bandwidth on all traffic",
			WantedLimit: true,
		},
		{
			name:        "should limit bandwidth only on port 5001 traffic",
			port:        []string{"5001"},
			WantedLimit: true,
		},
		{
			name:        "should limit bandwidth only on port 80 traffic",
			port:        []string{"80"},
			WantedLimit: false,
		},
		{
			name:        "should limit bandwidth only traffic for iperf server",
			ip:          []string{iperf.ServerIp},
			WantedLimit: true,
		},
	}

	unlimited, err := iperf.MeasureBandwidth()
	require.NoError(t, err)
	limited := unlimited / 3

	for _, tt := range tests {
		config := struct {
			Duration     int      `json:"duration"`
			Bandwidth    string   `json:"bandwidth"`
			Ip           []string `json:"ip"`
			Hostname     []string `json:"hostname"`
			Port         []string `json:"port"`
			NetInterface []string `json:"networkInterface"`
		}{
			Duration:     30000,
			Bandwidth:    fmt.Sprintf("%dmbit", int(limited)),
			Ip:           tt.ip,
			Hostname:     tt.hostname,
			Port:         tt.port,
			NetInterface: tt.interfaces,
		}

		t.Run(tt.name, func(t *testing.T) {
			action, err := e.RunAction(exthost.BaseActionID+".network_bandwidth", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			if tt.WantedLimit {
				iperf.AssertBandwidth(t, limited*0.95, limited*1.05)
			} else {
				iperf.AssertBandwidth(t, unlimited*0.95, unlimited*1.05)
			}
			require.NoError(t, action.Cancel())
			iperf.AssertBandwidth(t, unlimited*0.95, unlimited*1.05)
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testNetworkBlockDns(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testNetworkBlockDns")
	nginx := e2e.Nginx{Minikube: m}
	err := nginx.Deploy("nginx-network-block-dns")
	require.NoError(t, err, "failed to create pod")
	defer func() { _ = nginx.Delete() }()

	tests := []struct {
		name             string
		ip               []string
		hostname         []string
		dnsPort          uint
		WantedReachable  bool
		WantedReachesUrl bool
	}{
		{
			name:             "should block dns traffic",
			dnsPort:          53,
			WantedReachable:  true,
			WantedReachesUrl: false,
		},
		{
			name:             "should block dns traffic on port 5353",
			dnsPort:          5353,
			WantedReachable:  true,
			WantedReachesUrl: true,
		},
		{
			name:             "should block dns only traffic for steadybit.com",
			dnsPort:          53,
			hostname:         []string{"steadybit.com"},
			WantedReachable:  true,
			WantedReachesUrl: false,
		},
	}

	for _, tt := range tests {
		config := struct {
			Duration int  `json:"duration"`
			DnsPort  uint `json:"dnsPort"`
		}{
			Duration: 10000,
			DnsPort:  tt.dnsPort,
		}

		t.Run(tt.name, func(t *testing.T) {
			nginx.AssertIsReachable(t, true)
			nginx.AssertCanReach(t, "https://steadybit.com", true)

			action, err := e.RunAction(exthost.BaseActionID+".network_block_dns", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			nginx.AssertIsReachable(t, tt.WantedReachable)
			if tt.WantedReachesUrl {
				nginx.AssertCanReach(t, "https://steadybit.com", true)
			} else {
				nginx.AssertCannotReach(t, "https://steadybit.com", "Resolving timed out after")
			}

			require.NoError(t, action.Cancel())
			nginx.AssertIsReachable(t, true)
			nginx.AssertCanReach(t, "https://steadybit.com", true)
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func testFillDisk(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	pathToFill := "/filldisk"
	err := m.SshExec("sudo", "mkdir", "-p", pathToFill).Run()
	require.NoError(t, err)

	var getDiskSpace = func(m *e2e.Minikube) diskfill.DiskUsage {
		dfOutput, err := runInMinikube(m, "df", "--sync", "-k", "--output=source,target,fstype,file,size,avail,used", pathToFill)
		require.NoError(t, err)

		diskSpace, err := diskfill.CalculateDiskUsage(bytes.NewReader(dfOutput))
		require.NoError(t, err)

		log.Debug().Msgf("Disk usage on Host: %+v", diskSpace)
		return diskSpace
	}

	type testCase struct {
		name           string
		mode           diskfill.Mode
		size           int
		blockSize      int
		method         diskfill.Method
		wantedFileSize func(m *e2e.Minikube) int
		wantedDelta    int
	}
	testCases := []testCase{
		{
			name:      "fill disk with percentage (fallocate)",
			mode:      diskfill.Percentage,
			size:      80,
			blockSize: 0,
			method:    diskfill.AtOnce,
			wantedFileSize: func(m *e2e.Minikube) int {
				diskSpace := getDiskSpace(m)
				return int(((diskSpace.Capacity * 80 / 100) - diskSpace.Used) / 1024)
			},
			wantedDelta: 512,
		},
		{
			name:      "fill disk with megabytes to fill (fallocate)",
			mode:      diskfill.MBToFill,
			size:      4 * 1024, // 4GB
			blockSize: 0,
			method:    diskfill.AtOnce,
			wantedFileSize: func(_ *e2e.Minikube) int {
				return 4 * 1024
			},
			wantedDelta: 0,
		},
		{
			name:      "fill disk with megabytes left (fallocate)",
			mode:      diskfill.MBLeft,
			size:      4 * 1024, // 4GB
			blockSize: 0,
			method:    diskfill.AtOnce,
			wantedFileSize: func(m *e2e.Minikube) int {
				diskSpace := getDiskSpace(m)
				return int(diskSpace.Available-(int64(4*1024*1024))) / 1024
			},
			wantedDelta: 512,
		},
		{
			name:      "fill disk with percentage (dd)",
			mode:      diskfill.Percentage,
			size:      70,
			blockSize: 5,
			method:    diskfill.OverTime,
			wantedFileSize: func(m *e2e.Minikube) int {
				diskSpace := getDiskSpace(m)
				return int(((diskSpace.Capacity * 70 / 100) - diskSpace.Used) / 1024)
			},
			wantedDelta: 512,
		},
		{
			name:      "fill disk with megabytes to fill (dd)",
			mode:      diskfill.MBToFill,
			size:      4 * 1024, // 4GB
			blockSize: 1,
			method:    diskfill.OverTime,
			wantedFileSize: func(_ *e2e.Minikube) int {
				return 4 * 1024
			},
			wantedDelta: 0,
		},
		{
			name:      "fill disk with megabytes left (dd)",
			mode:      diskfill.MBLeft,
			size:      1 * 1024,
			blockSize: 5,
			method:    diskfill.OverTime,
			wantedFileSize: func(m *e2e.Minikube) int {
				diskSpace := getDiskSpace(m)
				return int(diskSpace.Available-(int64(1*1024*1024))) / 1024
			},
			wantedDelta: 512,
		},
		{
			name:      "fill disk with bigger blocksize (dd)",
			mode:      diskfill.MBToFill,
			size:      4 * 1024, // 4GB
			blockSize: 6 * 1024, // 2GB
			method:    diskfill.OverTime,
			wantedFileSize: func(_ *e2e.Minikube) int {
				return 4 * 1024 // 4GB
			},
			wantedDelta: 512,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := struct {
				Duration  int    `json:"duration"`
				Path      string `json:"path"`
				Size      int    `json:"size"`
				Mode      string `json:"mode"`
				BlockSize int    `json:"blocksize"`
				Method    string `json:"method"`
			}{Duration: 60_000, Size: testCase.size, Mode: string(testCase.mode), Method: string(testCase.method), BlockSize: testCase.blockSize, Path: pathToFill}
			wantedFileSize := testCase.wantedFileSize(m)
			action, err := e.RunAction(fmt.Sprintf("%s.fill_disk", exthost.BaseActionID), getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			if testCase.method == diskfill.OverTime {
				e2e.AssertProcessRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "dd", true)
			}

			assertFileHasSize(t, m, "/filldisk/disk-fill", wantedFileSize, testCase.wantedDelta)
			require.NoError(t, action.Cancel())

			if testCase.method == diskfill.OverTime {
				e2e.AssertProcessNOTRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "dd")
			} else {
				e2e.AssertProcessNOTRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "fallocate")
			}

			out, _ := runInMinikube(m, "ls", "/filldisk/disk-fill")
			assert.Contains(t, string(out), "No such file or directory")
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

func assertFileHasSize(t *testing.T, m *e2e.Minikube, filepath string, wantedSizeInMb int, wantedDeltaInMb int) {
	sizeInBytes := wantedSizeInMb * 1024 * 1024
	deltaInBytes := wantedDeltaInMb * 1024 * 1024
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	message := ""
	for {
		select {
		case <-ctx.Done():
			assert.Fail(t, "file has not the expected size", message)
			return

		case <-time.After(200 * time.Millisecond):
			out, err := runInMinikube(m, "stat", "-c", "%s", filepath)
			if err != nil {
				message = fmt.Sprintf("%s: %s", err.Error(), out)
				continue
			}
			if fileSize, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
				actualDelta := int(math.Abs(float64(fileSize - sizeInBytes)))
				if actualDelta <= deltaInBytes {
					return
				} else {
					message = fmt.Sprintf("file size is %d, wanted %d, delta of %d exceeds allowed delta of %d", fileSize, sizeInBytes, actualDelta, deltaInBytes)
				}
			} else {
				message = fmt.Sprintf("cannot parse file size: %s", err.Error())
			}
		}
	}
}

func runInMinikube(m *e2e.Minikube, arg ...string) ([]byte, error) {
	cmd := m.SshExec(arg...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.CombinedOutput()
}

func requireAllSidecarsCleanedUp(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	out, err := m.PodExec(e.Pod, "steadybit-extension-host", "ls", "/run/steadybit/runc")
	require.NoError(t, err)
	space := strings.TrimSpace(out)
	require.Empty(t, space, "no sidecar directories must be present")
}

func getMinikubeOptions() e2e.MinikubeOpts {
	var runtimes []e2e.Runtime
	if rawRuntimes, _ := os.LookupEnv("E2E_RUNTIMES"); rawRuntimes != "" {
		runtimes = []e2e.Runtime{}
	OUTER:
		for _, rawRuntime := range strings.Split(rawRuntimes, ",") {
			lower := strings.ToLower(strings.TrimSpace(rawRuntime))
			for _, runtime := range e2e.AllRuntimes {
				if lower == string(runtime) {
					runtimes = append(runtimes, runtime)
					continue OUTER
				}
			}
			log.Info().Msgf("Ignoring unknown runtime %s", rawRuntime)
		}
	} else {
		runtimes = e2e.AllRuntimes
	}

	mOpts := e2e.DefaultMinikubeOpts().WithRuntimes(runtimes...)

	if exec.Command("kvm-ok").Run() != nil {
		log.Info().Msg("KVM is not available, using docker driver")
		mOpts = mOpts.WithDriver("docker")
	} else {
		log.Info().Msg("KVM is available, using kvm2 driver")
		mOpts = mOpts.WithDriver("kvm2")
	}

	return mOpts
}
