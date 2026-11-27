<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0015: A Kubernetes operator written against the API server's REST API

- Status: Accepted, implemented in 0.0.21
- Date: 2026-11-27

## Context

The Helm chart (0.0.17) deploys one gateway from values. A platform team
wants more: gateways declared as resources, connector route ownership
and tool policies kept beside the workloads they protect, each owned by
the team that owns the workload, and the gateway kept in step when any
of them changes. `kube` 5.2.0 (with `runtime`, `derive` and
`rustls-tls`) and `k8s-openapi` 0.29.0 would add 132 packages not
already in `Cargo.lock`, measured on 2026-11-27 (D9); the API
server's REST API is plain HTTPS and JSON, which the repository already
speaks with hyper and rustls.

## Decision

**One binary.** `tunnelward operator` runs from the same image as the
gateway: in the cluster with its service account by default, or against
`--server`, `--token-file` and `--ca` for development.

**Data.** Three namespaced custom resources in
`tunnelward.satellion.com/v1alpha1`:

```text
TunnelwardGateway { image, replicas, tlsSecret, ingressTlsSecret?,
                    adminTokenSecret?, serviceType, config? }
ConnectorBinding  { gateway, identity (SPIFFE ID), routes[] }
RoutePolicy       { gateway, policy (the policy file, TOML) }
```

A gateway's file is rendered from its `TunnelwardGateway` (listeners,
TLS, admin, the extra `config`), every `ConnectorBinding` naming it (one
`[[connectors.owners]]` per route, the identities of all its bindings),
and its `RoutePolicy`, written beside the file as `policy.toml`. The
operator writes the ConfigMap, Deployment and Services the Helm chart
writes, under the same security settings, owned by the
`TunnelwardGateway`, so deleting it deletes them.

**Checks before anything is written.** The rendered file must parse as a
gateway file, the policy as a policy (the gateway's own parsers), each
identity must be a SPIFFE ID, and a gateway takes one `RoutePolicy`.
When any check fails, the gateway's objects are left as they are and the
resource that failed says why in its status. A broken change never
reaches a running gateway.

**Reconciling.** Every `every_secs` (10 s) the operator lists the three
resources in its namespace and renders each gateway. What changed is
applied with server-side apply (`fieldManager=tunnelward-operator`);
everything is applied again every 300 s, which corrects drift. The
Deployment's pod template carries the SHA-256 of the rendered files, so
a change rolls the pods. Each resource's status carries conditions
(`Ready`, `Accepted`, `Bound`) and the generation they describe.

**RBAC.** A Role in the operator's namespace: read the three resources,
write their status, and manage ConfigMaps, Services and Deployments.

## Consequences

- Polling, not watching: a change takes up to `every_secs` to apply. A
  watch is the next step once the polling loop has run in production.
- One namespace per operator; a cluster-wide operator needs a
  ClusterRole and is not offered yet.
- The end-to-end test needs a cluster: `scripts/operator-e2e.sh` runs it
  against any API server it is given (k3s in colima, here). CI does not
  run it, since a cluster in CI would add a tool (D9).

## Alternatives

- **`kube` and `k8s-openapi`**: 132 more packages for a client we need
  four verbs of.
- **Helm only**: no reaction to bindings and policies owned elsewhere.
- **A Go operator with controller-runtime**: a second language and its
  tree, for the same REST calls.
