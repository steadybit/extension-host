// Copyright 2025 steadybit GmbH. All rights reserved.

package main

import (
	_ "github.com/KimMachineGun/automemlimit" // By default, it sets `GOMEMLIMIT` to 90% of cgroup's memory limit.
	"github.com/rs/zerolog"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/ociruntime"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/steadybit/discovery-kit/go/discovery_kit_api"
	"github.com/steadybit/discovery-kit/go/discovery_kit_sdk"
	"github.com/steadybit/extension-host/config"
	"github.com/steadybit/extension-host/exthost"
	"github.com/steadybit/extension-host/exthost/resources"
	"github.com/steadybit/extension-kit/extbuild"
	"github.com/steadybit/extension-kit/exthealth"
	"github.com/steadybit/extension-kit/exthttp"
	"github.com/steadybit/extension-kit/extlogging"
	"github.com/steadybit/extension-kit/extruntime"
	"github.com/steadybit/extension-kit/extsignals"
	_ "go.uber.org/automaxprocs" // Importing automaxprocs automatically adjusts GOMAXPROCS.
)

func main() {
	// Most Steadybit extensions leverage zerolog. To encourage persistent logging setups across extensions,
	// you may leverage the extlogging package to initialize zerolog. Among others, this package supports
	// configuration of active log levels and the log format (JSON or plain text).
	//
	// Example
	//  - to activate JSON logging, set the environment variable STEADYBIT_LOG_FORMAT="json"
	//  - to set the log level to debug, set the environment variable STEADYBIT_LOG_LEVEL="debug"
	extlogging.InitZeroLog()

	resources.AdjustOOMScoreAdj()

	// Build information is set at compile-time. This line writes the build information to the log.
	// The information is mostly handy for debugging purposes.
	extbuild.PrintBuildInformation()
	extruntime.LogRuntimeInformation(zerolog.InfoLevel)

	// Most extensions require some form of configuration. These calls exist to parse and validate the
	// configuration obtained from environment variables.
	config.ParseConfiguration()
	config.ValidateConfiguration()

	//This will start /health/liveness and /health/readiness endpoints on port 8081 for use with kubernetes
	//The port can be configured using the STEADYBIT_EXTENSION_HEALTH_PORT environment variable
	exthealth.SetReady(false)
	exthealth.StartProbes(int(config.Config.HealthPort))

	// This call registers a handler for the extension's root path. This is the path initially accessed
	// by the Steadybit agent to obtain the extension's capabilities.
	exthttp.RegisterHttpHandler("/", exthttp.GetterAsHandler(getExtensionList))

	r := ociruntime.NewOciRuntimeWithCrunForSidecars(ociruntime.ConfigFromEnvironment())

	// This is a section you will most likely want to change: The registration of HTTP handlers
	// for your extension. You might want to change these because the names do not fit, or because
	// you do not have a need for all of them.
	discovery_kit_sdk.Register(exthost.NewHostDiscovery())
	action_kit_sdk.RegisterAction(exthost.NewStressCpuAction(r))
	action_kit_sdk.RegisterAction(exthost.NewCpuSpeedAction())
	action_kit_sdk.RegisterAction(exthost.NewStressMemoryAction(r))
	action_kit_sdk.RegisterAction(exthost.NewStressIoAction(r))
	action_kit_sdk.RegisterAction(exthost.NewTimetravelAction(r))
	action_kit_sdk.RegisterAction(exthost.NewStopProcessAction())
	action_kit_sdk.RegisterAction(exthost.NewShutdownAction())
	action_kit_sdk.RegisterAction(exthost.NewNetworkBlackholeContainerAction(r))
	action_kit_sdk.RegisterAction(exthost.NewNetworkLimitBandwidthContainerAction(r))
	action_kit_sdk.RegisterAction(exthost.NewNetworkCorruptPackagesContainerAction(r))
	action_kit_sdk.RegisterAction(exthost.NewNetworkDelayContainerAction(r))
	action_kit_sdk.RegisterAction(exthost.NewNetworkBlockDnsContainerAction(r))
	action_kit_sdk.RegisterAction(exthost.NewNetworkPackageLossContainerAction(r))
	action_kit_sdk.RegisterAction(exthost.NewFillDiskHostAction(r))
	action_kit_sdk.RegisterAction(exthost.NewFillMemoryHostAction(r))

	//This will install a signal handler, that will stop active actions when receiving a SIGURS1, SIGTERM or SIGINT
	extsignals.ActivateSignalHandlers()

	action_kit_sdk.RegisterCoverageEndpoints()

	//This will switch the readiness state of the application to true.
	exthealth.SetReady(true)

	exthttp.Listen(exthttp.ListenOpts{
		// This is the default port under which your extension is accessible.
		// The port can be configured externally through the
		// STEADYBIT_EXTENSION_PORT environment variable.
		Port: int(config.Config.Port),
	})
}

// ExtensionListResponse exists to merge the possible root path responses supported by the
// various extension kits. In this case, the response for ActionKit, DiscoveryKit and EventKit.
type ExtensionListResponse struct {
	action_kit_api.ActionList       `json:",inline"`
	discovery_kit_api.DiscoveryList `json:",inline"`
}

func getExtensionList() ExtensionListResponse {
	return ExtensionListResponse{
		// See this document to learn more about the action list:
		// https://github.com/steadybit/action-kit/blob/main/docs/action-api.md#action-list
		ActionList: action_kit_sdk.GetActionList(),

		// See this document to learn more about the discovery list:
		// https://github.com/steadybit/discovery-kit/blob/main/docs/discovery-api.md#index-response
		DiscoveryList: discovery_kit_sdk.GetDiscoveryList(),
	}
}
