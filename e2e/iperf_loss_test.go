// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package e2e

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/steadybit/action-kit/go/action_kit_test/e2e"
	acorev1 "k8s.io/client-go/applyconfigurations/core/v1"
)

// deployIperf deploys the kit's iperf pods, with a server that resets itself if a test
// aborted by the attack leaves it stuck, instead of waiting for the attack to end.
func deployIperf(iperf *e2e.Iperf, name string) error {
	return iperf.Deploy(name, func(server *acorev1.PodApplyConfiguration, _ *acorev1.PodApplyConfiguration) {
		server.Spec.Containers[0].Args = []string{"-s", "-p", "5201", "--idle-timeout", "5"}
	})
}

// measurePackageLoss is a more robust variant of e2e.Iperf.MeasurePackageLoss.
// The kit's measurement sends ~250 datagrams (2s at iperf's default 1 Mbit/s),
// so at 10% loss one reading has a standard deviation of ~2 points; at 10 Mbit/s
// it is ~0.6 points and a single reading reliably lands in the expected range.
// Under the attack an iperf run now and then hangs until the attack ends; timeout cuts it
// off so the next reading still happens while the attack is active.
func measurePackageLoss(iperf *e2e.Iperf) (float64, error) {
	out, err := iperf.Minikube.PodExec(iperf.ClientPod, "iperf", "timeout", "8", "iperf3", "--client", iperf.ServerIp, "--port=5201", "--udp", "--time=2", "--length=1k", "--bitrate=10M", "--bind=0.0.0.0", "--reverse", "--cport=5001", "--connect-timeout=3000", "--no-delay", "--zerocopy", "--json")
	if err != nil {
		return 0, fmt.Errorf("%w: %s", err, out)
	}

	var result struct {
		End struct {
			Sum struct {
				LostPercent *float64 `json:"lost_percent"`
			} `json:"sum"`
		} `json:"end"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return 0, fmt.Errorf("failed reading results: %w", err)
	}
	if result.End.Sum.LostPercent == nil {
		return 0, fmt.Errorf("no lost_percent in results: %s", out)
	}
	return *result.End.Sum.LostPercent, nil
}

// awaitPackageLoss measures until the loss is within [min, max], up to attempts times.
// Failed iperf runs are retried too: the attacks also hit iperf's TCP control
// connection, which now and then makes iperf abort (e.g. "unable to read from stream socket").
func awaitPackageLoss(iperf *e2e.Iperf, min, max float64, attempts int) error {
	var measurements []float64
	var errs []error
	for i := range attempts {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		loss, err := measurePackageLoss(iperf)
		if err != nil {
			log.Warn().Err(err).Msg("iperf run failed")
			errs = append(errs, err)
			continue
		}
		if loss >= min && loss <= max {
			return nil
		}
		log.Info().Msgf("package loss %.2f is not in expected range [%.1f, %.1f]", loss, min, max)
		measurements = append(measurements, loss)
	}
	return fmt.Errorf("package loss %v is not in expected range [%.1f, %.1f] (%d iperf runs failed, last error: %v)", measurements, min, max, len(errs), lastErr(errs))
}

func lastErr(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return errs[len(errs)-1]
}
