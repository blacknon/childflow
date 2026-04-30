# Docker E2E

This directory contains a closed Docker-based end-to-end environment for `childflow`.

It provides:

- `origin-routed-http`
  a web origin on a routed-only subnet
- `ping-target`
  an ICMP target on that same routed-only subnet
- `proxy-http`
  an authenticated HTTP proxy that can reach the routed subnet
- `route-gateway`
  a gateway container that forwards traffic from the client subnet to the routed subnet
- `childflow-e2e`
  a privileged runner that builds `childflow` and executes the end-to-end checks

The e2e script verifies:

- the runner cannot reach the routed subnet directly before a static route is installed
- a proxied `childflow` HTTP request can still reach the routed web origin without that route
- after adding a route through `route-gateway`, `childflow` can reach the routed web origin directly
- after that same route is installed, `childflow` can `ping` the routed ICMP target
- capture files are written for both proxied and routed flows

## Run

```bash
docker compose -f docker/e2e/compose.yml run --build --rm childflow-e2e bash /workspaces/childflow/docker/e2e/run-e2e.sh
```
