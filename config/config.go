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
	// NetworkStrictRootQdisc, when true, makes network attacks refuse (in the
	// prepare step) any target interface whose root qdisc is not `noqueue` —
	// including the kernel default `mq` on managed-cloud nodes. Opt-in fallback
	// for customers who don't want attacks to replace a pre-existing root qdisc.
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
