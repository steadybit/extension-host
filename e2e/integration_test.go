// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package e2e

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_test/e2e"
	"github.com/steadybit/discovery-kit/go/discovery_kit_api"
	"github.com/steadybit/discovery-kit/go/discovery_kit_test/validate"
	"github.com/steadybit/extension-host/exthost"
	"github.com/steadybit/extension-kit/extutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
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

func runsInCi() bool {
	return os.Getenv("CI") != ""
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

	e2e.WithDefaultMinikube(t, &extFactory, []e2e.WithMinikubeTestCase{
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
		// deactivated cause otherwise the shutdown will prevent the coverage collection from the tests above
		//{
		// must be the last test, because it will shutdown the minikube host (minikube cannot be restarted)
		//Name: "shutdown host",
		//Test: testShutdownHost, // if you run this test locally, you will need to restart your docker machine
		//},
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
			}{Duration: 2000000, Workers: 1, MbytesPerWorker: 50, Path: "/stressng", Mode: mode}

			action, err := e.RunAction("com.steadybit.extension_host.stress-io", getTarget(m), config, executionContext)
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			time.Sleep(2000 * time.Second)

			e2e.AssertProcessRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "stress-ng", true)
			require.NoError(t, action.Cancel())
			e2e.AssertProcessNOTRunningInContainer(t, m, e.Pod, "steadybit-extension-host", "stress-ng")

			cmd := m.SshExec("ls", "/stressng")
			cmd.Stdout = nil
			cmd.Stderr = nil
			out, err := cmd.CombinedOutput()
			require.NoError(t, err)
			require.Empty(t, strings.TrimSpace(string(out)), "no stress-ng directories must be present")
		})
	}
}

func testTimeTravel(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	log.Info().Msg("Starting testTimeTravel")
	config := struct {
		Duration   int  `json:"duration"`
		Offset     int  `json:"offset"`
		DisableNtp bool `json:"disableNtp"`
	}{Duration: 30000, Offset: int((360 * time.Second).Milliseconds()), DisableNtp: true}

	duration := float64(time.Duration(config.Offset) * time.Millisecond)
	min := float64(duration) * 0.8
	max := float64(duration) * 1.2

	now := time.Now()
	action, err := e.RunAction("com.steadybit.extension_host.timetravel", getTarget(m), config, nil)

	require.NoError(t, err)
	defer func() { _ = action.Cancel() }()
	require.NoError(t, err)
	diff := getTimeDiffBetweenNowAndContainerTime(t, m, e, now)
	log.Debug().Msgf("diff: %f", diff.Seconds())
	// check if is in tolerance
	assert.True(t, min <= float64(diff) && float64(diff) <= max, "time travel failed")

	// rollback
	require.NoError(t, action.Cancel())

	now = time.Now()
	diff = getTimeDiffBetweenNowAndContainerTime(t, m, e, now)
	log.Debug().Msgf("diff: %f", diff.Seconds())
	assert.True(t, min <= float64(diff) && float64(diff) <= max, "time travel failed to rollback properly")

}

func getTimeDiffBetweenNowAndContainerTime(t *testing.T, m *e2e.Minikube, e *e2e.Extension, now time.Time) time.Duration {
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
	diff := containerTime.Sub(now)
	if diff < 0 {
		diff = diff * -1
	}
	return diff
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
			if runsInCi() {
				time.Sleep(5 * time.Second)
			}
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
				if runsInCi() {
					time.Sleep(5 * time.Second)
				}
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
}
