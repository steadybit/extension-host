/*
 * Copyright 2023 steadybit GmbH. All rights reserved.
 */

package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

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
	// TLSInterceptCaCert / TLSInterceptCaKey point at a PEM certificate authority
	// used by 'Intercept Outgoing HTTP Request' to mint per-hostname certificates, which is
	// what lets it return a synthesized response for an HTTPS dependency instead
	// of cleartext HTTP only. Unset (the default) leaves HTTPS untouched.
	//
	// The CA is the customer's: they generate it, choose its validity, and install
	// it in the truststores of the workloads they want to fault. Because it can
	// impersonate any HTTPS endpoint to anything trusting it, mount it from a
	// Secret and keep this to test environments.
	// STEADYBIT_EXTENSION_TLS_INTERCEPT_CA_CERT / _KEY
	TLSInterceptCaCert string `json:"tlsInterceptCaCert" split_words:"true" required:"false"`
	TLSInterceptCaKey  string `json:"tlsInterceptCaKey" split_words:"true" required:"false"`
	// TLSInterceptLeafValidity is how long the per-hostname certificates the
	// proxy mints stay valid. Shorter narrows the window in which a leaf that
	// escaped the proxy could be used; it is always clamped to the CA's own
	// expiry. Empty keeps the proxy's default (24h).
	// STEADYBIT_EXTENSION_TLS_INTERCEPT_LEAF_VALIDITY
	TLSInterceptLeafValidity time.Duration `json:"tlsInterceptLeafValidity" split_words:"true" required:"false"`
}

// TLSInterceptEnabled reports whether HTTPS response injection is configured.
func (s Specification) TLSInterceptEnabled() bool {
	return s.TLSInterceptCaCert != "" && s.TLSInterceptCaKey != ""
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
	// Not fatal: see validateInterceptCA. HTTPS interception is opt-in, so a CA
	// that cannot be read disables it and leaves the rest of the extension
	// working, rather than taking the node's discovery and attacks with it.
	if err := Config.validateInterceptCA(); err != nil {
		log.Error().Err(err).Msg("HTTPS interception is configured but unusable; it will be unavailable until this is fixed")
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

	// Half a CA is never usable, and the resulting failure (every interception
	// handshake failing) is far harder to diagnose than refusing to start.
	if (s.TLSInterceptCaCert == "") != (s.TLSInterceptCaKey == "") {
		return fmt.Errorf("STEADYBIT_EXTENSION_TLS_INTERCEPT_CA_CERT and STEADYBIT_EXTENSION_TLS_INTERCEPT_CA_KEY must be set together")
	}
	return nil
}

// validateInterceptCA reports whether the configured CA is actually loadable.
//
// The result is logged, never fatal. HTTPS interception is opt-in, and its
// Secret is mounted optional precisely so a missing, renamed or mid-rotation
// one cannot take the extension down — killing the process here would undo
// that and cost all discovery and every attack on the node. An attack that
// actually needs the CA still fails at Prepare, naming the file it could not
// read, so a broken CA is never mistaken for working interception.
func (s Specification) validateInterceptCA() error {
	if !s.TLSInterceptEnabled() {
		return nil
	}
	certPEM, err := os.ReadFile(s.TLSInterceptCaCert)
	if err != nil {
		return fmt.Errorf("cannot read STEADYBIT_EXTENSION_TLS_INTERCEPT_CA_CERT: %w", err)
	}
	keyPEM, err := os.ReadFile(s.TLSInterceptCaKey)
	if err != nil {
		return fmt.Errorf("cannot read STEADYBIT_EXTENSION_TLS_INTERCEPT_CA_KEY: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("the configured TLS interception CA is not a usable certificate/key pair: %w", err)
	}
	return nil
}
