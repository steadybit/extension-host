/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package config

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/zerolog/log"
)

// Specification is the configuration specification for the extension. Configuration values can be applied
// through environment variables. Learn more through the documentation of the envconfig package.
// https://github.com/kelseyhightower/envconfig
type Specification struct {
	Port                            uint16   `json:"port" split_words:"true" required:"false" default:"8085"`
	HealthPort                      uint16   `json:"healthPort" split_words:"true" required:"false" default:"8081"`
	DiscoveryAttributesExcludesHost []string `json:"discoveryAttributesExcludesHost" split_words:"true" required:"false"`
	Hostname                        string   `json:"hostname" split_words:"true" required:"false"`
	DisableRunc                     bool     `json:"disableRunc" split_words:"true" required:"false"`
	// NetworkStrictRootQdisc controls how network attacks behave on
	// interfaces whose root qdisc isn't `noqueue` (e.g. the kernel default
	// `mq` on managed-cloud nodes):
	//   - true (default): refuse the attack in the prepare step.
	//   - false: install the attack, but snapshot the root qdisc tree
	//     beforehand and replay it on revert so the cloud-tuned state
	//     (e.g. GKE's `mq + fq` with `buckets=32768 horizon=2s`) is
	//     preserved instead of being reset to kernel defaults.
	// STEADYBIT_EXTENSION_NETWORK_STRICT_ROOT_QDISC
	NetworkStrictRootQdisc bool `json:"networkStrictRootQdisc" split_words:"true" required:"false" default:"true"`
}

var (
	Config Specification
)

func ParseConfiguration() {
	err := envconfig.Process("steadybit_extension", &Config)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to parse configuration from environment.")
	}
}

func ValidateConfiguration() {
	// You may optionally validate the configuration here.
}
