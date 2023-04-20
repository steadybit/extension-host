# Steadybit extension-host

*Open Beta: This extension generally works, but you may discover some rough edges.*

This extension provides a Host discovery and the following attacks for host targets:

 - stress CPU
 - stress Memory
 - stress Disk
 -

## Configuration

| Environment Variable                  | Meaning                                                                                                                                                                | Default |
|---------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `STEADYBIT_DISCOVERY_ENV_LIST`        | List of environment variables to inlude in the discovery                                                                                                               |         |
| `STEADYBIT_EXTENSION_PORT`            | Port number that the HTTP server should bind to.                                                                                                                       | 8085    |
| `STEADYBIT_EXTENSION_TLS_SERVER_CERT` | Optional absolute path to a TLS certificate that will be used to open an **HTTPS** server.                                                                             |         |
| `STEADYBIT_EXTENSION_TLS_SERVER_KEY`  | Optional absolute path to a file containing the key to the server certificate.                                                                                         |         |
| `STEADYBIT_EXTENSION_TLS_CLIENT_CAS`  | Optional comma-separated list of absolute paths to files containing TLS certificates. When specified, the server will expect clients to authenticate using mutual TLS. |         |
| `STEADYBIT_LOG_FORMAT`                | Defines the log format that the extension will use. Possible values are `text` and `json`.                                                                             | text    |
| `STEADYBIT_LOG_LEVEL`                 | Defines the active log level. Possible values are `debug`, `info`, `warn` and `error`.                                                                                 | info    |

## Running the Extension

### Using Docker

```sh
$ docker run \
  --rm \
  -p 8085 \
  --name steadybit-extension-host \
  ghcr.io/steadybit/extension-host:latest
```

### Using Helm in Kubernetes

```sh
$ helm repo add steadybit-extension-host https://steadybit.github.io/extension-host
$ helm repo update
$ helm upgrade steadybit-extension-host \
    --install \
    --wait \
    --timeout 5m0s \
    --create-namespace \
    --namespace steadybit-extension \
    steadybit-extension-host/steadybit-extension-host
```
