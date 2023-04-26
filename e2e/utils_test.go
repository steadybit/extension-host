// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 Steadybit GmbH

package e2e

import (
  "bufio"
  "bytes"
  "context"
  "errors"
  "fmt"
  "github.com/rs/zerolog/log"
  "github.com/steadybit/action-kit/go/action_kit_api/v2"
  "github.com/steadybit/discovery-kit/go/discovery_kit_api"
  "github.com/stretchr/testify/assert"
  "github.com/stretchr/testify/require"
  appv1 "k8s.io/api/apps/v1"
  corev1 "k8s.io/api/core/v1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  "k8s.io/apimachinery/pkg/labels"
  "strings"
  "testing"
  "time"
)

func assertProcessRunningInContainer(t *testing.T, m *Minikube, pod metav1.Object, containername string, comm string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lastOutput := ""
	for {
		select {
		case <-ctx.Done():
			assert.Failf(t, "process not found", "process %s not found in container %s/%s.\n%s", comm, pod.GetName(), containername, lastOutput)
			return

		case <-time.After(200 * time.Millisecond):
			out, err := m.Exec(pod, containername, "ps", "-opid,comm", "-A")
			require.NoError(t, err, "failed to exec ps -o=pid,comm: %s", out)

			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == comm {
					return
				}
			}
			lastOutput = out
		}
	}
}

func assertProcessNOTRunningInContainer(t *testing.T, m *Minikube, pod metav1.Object, containername string, comm string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lastOutput := ""
	for {
		select {
		case <-ctx.Done():
			return

		case <-time.After(200 * time.Millisecond):
			out, err := m.Exec(pod, containername, "ps", "-opid,comm", "-A")
			require.NoError(t, err, "failed to exec ps -o=pid,comm: %s", out)

			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == comm {
          assert.Fail(t, "process found", "process %s found in container %s/%s.\n%s", comm, pod.GetName(), containername, lastOutput)
					return
				}
			}
			lastOutput = out
		}
	}
}

func NewContainerTarget(m *Minikube, pod metav1.Object, containername string) (*action_kit_api.Target, error) {
	status, err := GetContainerStatus(m, pod, containername)
	if err != nil {
		return nil, err
	}
	return &action_kit_api.Target{
		Attributes: map[string][]string{
			"container.id": {status.ContainerID},
		},
	}, nil
}

func GetContainerStatus(m *Minikube, pod metav1.Object, containername string) (*corev1.ContainerStatus, error) {
	r, err := m.GetPod(pod)
	if err != nil {
		return nil, err
	}

	for _, status := range r.Status.ContainerStatuses {
		if status.Name == containername {
			return &status, nil
		}
	}
	return nil, errors.New("container not found")
}

func waitForContainerStatusUsingContainerEngine(m *Minikube, containerId string, wantedStatus string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var lastError error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("container %s did not reach status %s. last error %w", containerId, wantedStatus, lastError)
		case <-time.After(200 * time.Millisecond):
			status, err := getContainerStatusUsingContainerEngine(m, containerId)
			if err != nil {
				lastError = err
			} else {
				if status == wantedStatus {
					return nil
				}
			}
		}
	}
}

func removePrefix(containerId string) string {
	if i := strings.Index(containerId, "://"); i >= 0 {
		return containerId[i+len("://"):]
	}
	return containerId
}
func getContainerStatusUsingContainerEngine(m *Minikube, containerId string) (string, error) {
	if strings.HasPrefix(containerId, "docker") {
		var outb bytes.Buffer
		cmd := m.exec("sudo docker", "inspect", "-f='{{.State.Status}}'", removePrefix(containerId))
		cmd.Stdout = &outb
		if err := cmd.Run(); err != nil {
			return "", err
		}
		return strings.TrimSpace(outb.String()), nil
	}

	return "", fmt.Errorf("unsupported container runtime")
}

func pollForTarget(ctx context.Context, e *Extension, predicate func(target discovery_kit_api.Target) bool) (discovery_kit_api.Target, error) {
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return discovery_kit_api.Target{}, fmt.Errorf("timed out waiting for target. last error: %w", lastErr)
		case <-time.After(200 * time.Millisecond):
			targets, err := e.DiscoverTargets("host")
			if err != nil {
				lastErr = err
				continue
			}
			for _, target := range targets {
				if predicate(target) {
					return target, nil
				}
			}
		}
	}
}

func hasAttribute(target discovery_kit_api.Target, key, value string) bool {
	for _, v := range target.Attributes[key] {
		if v == value {
			return true
		}
	}
	return false
}

func waitForPods(minikube *Minikube, daemonSet *appv1.DaemonSet) metav1.Object {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var podResult metav1.Object

	for {
		select {
		case <-ctx.Done():
			return podResult
		case <-time.After(200 * time.Millisecond):
		}

		pods, err := minikube.Client().CoreV1().Pods(daemonSet.GetNamespace()).List(ctx, metav1.ListOptions{
			LabelSelector: labels.Set(daemonSet.Spec.Selector.MatchLabels).String(),
		})
		if err != nil {
			log.Warn().Err(err).Msg("failed to list pods for extension")
		}

		for _, pod := range pods.Items {
			if err := minikube.WaitForPodPhase(pod.GetObjectMeta(), corev1.PodRunning, 10*time.Second); err != nil {
				log.Warn().Err(err).Msg("pod is not running")
			}
			podResult = pod.GetObjectMeta()
			go tailLog(minikube, pod.GetObjectMeta())
		}
		if len(pods.Items) > 0 {
			break
		}
	}
	return podResult
}

func tailLog(minikube *Minikube, pod metav1.Object) {
	reader, err := minikube.Client().CoreV1().
		Pods(pod.GetNamespace()).
		GetLogs(pod.GetName(), &corev1.PodLogOptions{
			Follow: true,
		}).Stream(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("failed to tail logs")
	}
	defer func() { _ = reader.Close() }()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fmt.Printf("📦%s\n", scanner.Text())
	}
}
