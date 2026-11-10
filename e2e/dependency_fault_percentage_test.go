// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_test/e2e"
	"github.com/steadybit/extension-host/exthost"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testNetworkDependencyFaultPercentage checks that Percentage applies per
// request on a keep-alive connection: on cleartext HTTP, and on HTTPS that the
// proxy decrypts with the interception CA. The requests are the node's own
// (curl on the node), since the host attack hooks the node's outgoing traffic.
func testNetworkDependencyFaultPercentage(t *testing.T, m *e2e.Minikube, e *e2e.Extension) {
	// The suite configures an interception CA; the node's curl trusts it over
	// HTTPS, as a customer's workload would.
	require.NoError(t, nodeWriteFile(m, nodeInterceptCAPath, interceptCA.certPEM), "failed to place the CA on the node")

	const host = "steadybit.com"

	tests := []struct {
		name, port, url string
		curlArgs        []string
	}{
		{name: "cleartext HTTP", port: "80", url: "http://" + host},
		{name: "HTTPS through the interception CA", port: "443", url: "https://" + host, curlArgs: []string{"--cacert", nodeInterceptCAPath}},
	}
	for _, tt := range tests {
		t.Run("intercept applies the percentage per request on a keep-alive connection over "+tt.name, func(t *testing.T) {
			config := map[string]any{
				"duration": 60000, "hostname": []string{host},
				"percentage": 50, "port": []string{tt.port}, "httpStatus": 503,
			}
			// Empty execution context, see testNetworkTcpResetL7AllPorts.
			action, err := e.RunAction(exthost.BaseActionID+".network_dependency_http_response", getTarget(m), config, &action_kit_api.ExecutionContext{})
			defer func() { _ = action.Cancel() }()
			require.NoError(t, err)

			// 100 requests over one curl connection. A per-connection roll would fault
			// all or none of them; per request, about half are faulted. 30..70 is
			// about 4 standard deviations at n=100.
			const requests = 100
			e2e.Retry(t, 10, 1*time.Second, func(r *e2e.R) {
				got, err := nodeCurlKeepAlive(m, tt.url, requests, tt.curlArgs...)
				if err != nil {
					r.Failed = true
					_, _ = fmt.Fprintf(r.Log, "requests failed: %v", err)
					return
				}
				if got.responses != requests || got.faulted < 30 || got.faulted > 70 || got.connects > 5 {
					r.Failed = true
					_, _ = fmt.Fprintf(r.Log, "expected %d responses, about half faulted, over one connection; got %d responses, %d faulted, over %d connections",
						requests, got.responses, got.faulted, got.connects)
				}
			})
			require.NoError(t, action.Cancel())
		})
	}
	requireAllSidecarsCleanedUp(t, m, e)
}

const nodeInterceptCAPath = "/tmp/steadybit-e2e-intercept-ca.crt"

// nodeCurlKeepAlive sends n GET requests to url from the node in a single curl
// call, which keeps one connection open for all of them, and summarizes the
// responses. extraArgs go before the URLs, e.g. --cacert for HTTPS. minikube
// ssh re-parses the command in a shell, which would mangle curl's write-out
// format, so the call runs from a script written to the node.
func nodeCurlKeepAlive(m *e2e.Minikube, url string, n int, extraArgs ...string) (keepAliveResult, error) {
	script := "curl --max-time 30 -s -w '%{http_code} %{num_connects}\\n' " + strings.Join(extraArgs, " ") +
		strings.Repeat(" -o /dev/null "+url, n) + "\n"
	const scriptPath = "/tmp/steadybit-e2e-keepalive.sh"
	if err := nodeWriteFile(m, scriptPath, []byte(script)); err != nil {
		return keepAliveResult{}, err
	}
	out, err := nodeExec(m, "sh", scriptPath)
	if err != nil {
		return keepAliveResult{}, fmt.Errorf("%w: %s", err, out)
	}
	return parseCurlWriteOut(string(out)), nil
}

// nodeWriteFile writes data to path on the node. It travels base64-encoded,
// which has nothing the shell behind minikube ssh would interpret.
func nodeWriteFile(m *e2e.Minikube, path string, data []byte) error {
	out, err := nodeExec(m, "echo", base64.StdEncoding.EncodeToString(data), "|", "base64", "-d", ">", path)
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// keepAliveResult summarizes nodeCurlKeepAlive: how many responses arrived,
// how many were the injected 503, and how many connections curl had to open.
type keepAliveResult struct {
	responses, faulted, connects int
}

// parseCurlWriteOut reads curl's "-w '%{http_code} %{num_connects}\n'" output.
// Splitting into fields drops a "\r" a TTY may add to each line, which would
// otherwise make every count unparsable.
func parseCurlWriteOut(out string) keepAliveResult {
	var r keepAliveResult
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		r.responses++
		if fields[0] == "503" {
			r.faulted++
		}
		if c, err := strconv.Atoi(fields[1]); err == nil {
			r.connects += c
		}
	}
	return r
}

const tlsInterceptSecretName = "e2e-intercept-ca"

// interceptCA is generated once per run and shared by the extension (which
// signs with it) and the node (which is asked to trust it).
var interceptCA struct {
	certPEM []byte
	keyPEM  []byte
}

func init() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Steadybit E2E Intercept CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	interceptCA.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	interceptCA.keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// createInterceptCASecret publishes the CA before the extension is installed,
// so the chart can mount it. Get-or-update rather than delete/create: the
// harness runs ExtraArgs on every helm upgrade, and churning a Secret under a
// live DaemonSet mount would be a self-inflicted flake.
func createInterceptCASecret(m *e2e.Minikube) error {
	client := m.GetClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: tlsInterceptSecretName, Namespace: "default"},
		Data:       map[string][]byte{"ca.crt": interceptCA.certPEM, "ca.key": interceptCA.keyPEM},
	}
	_, err := client.CoreV1().Secrets("default").Create(ctx, secret, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		_, err = client.CoreV1().Secrets("default").Update(ctx, secret, metav1.UpdateOptions{})
	}
	return err
}
