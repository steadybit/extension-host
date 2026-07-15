/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package config

import (
	"fmt"

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
	// FillMemoryReserve is the amount of memory the "fill memory" attack always leaves available so
	// the host's OS and kubelet stay responsive. Filling a Kubernetes node to a true 100% starves
	// the kubelet and takes the node NotReady; leaving this reserve avoids that. Accepts suffixes
	// K/M/G or % (parsed by the memfill binary). See ADM-1970.
	// STEADYBIT_EXTENSION_FILL_MEMORY_RESERVE
	FillMemoryReserve string `json:"fillMemoryReserve" split_words:"true" required:"false" default:"512MiB"`
	// FillMemoryOomScoreAdj is the oom_score_adj applied to the fill process. The default -996 sits
	// just above the agent/extension-host (-997), so if memory is ever exhausted the fill is killed
	// before the steadybit tooling, which stays alive to report and roll back.
	// STEADYBIT_EXTENSION_FILL_MEMORY_OOM_SCORE_ADJ
	FillMemoryOomScoreAdj int `json:"fillMemoryOomScoreAdj" split_words:"true" required:"false" default:"-996"`
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
	if err := Config.validate(); err != nil {
		log.Fatal().Msg(err.Error())
	}
}

func (s Specification) validate() error {
	// The kernel only accepts oom_score_adj in -1000..1000. memfill would silently clamp an
	// out-of-range value, handing the operator a score they did not ask for, so fail fast instead.
	if s.FillMemoryOomScoreAdj < -1000 || s.FillMemoryOomScoreAdj > 1000 {
		return fmt.Errorf("STEADYBIT_EXTENSION_FILL_MEMORY_OOM_SCORE_ADJ must be between -1000 and 1000, got %d", s.FillMemoryOomScoreAdj)
	}
	// FillMemoryReserve's format (bytes/K/M/G or %) is validated by the memfill binary; replicating
	// its parser here would risk drifting from it.
	return nil
}
