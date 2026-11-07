<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# ADR 0001: Reverse HTTP/2 instead of a custom multiplexer

- Status: Accepted
- Date: 2026-11-07

## Context

A connector sits in a private network and can only dial out. The gateway
must still send it many concurrent requests over the connection the
connector opened. Inverted proxies such as Cranker do this by
multiplexing their own frames over WebSockets. The audit of
mu-cranker-router found the defect classes that approach invites: frames
read without length checks, header buffers without limits, one bad frame
killing every stream on the socket, and flow control that trusts the
peer.

## Decision

Tunnelward does not define a multiplexing protocol. The connector dials
the gateway over TLS 1.3 with ALPN `tw/1` and sends one length-prefixed
`Register` frame (`tw-proto`). The gateway answers with one `Accept` or
`Reject`. After `Accept`, both sides switch the same stream to HTTP/2
with the roles reversed: the gateway runs the HTTP/2 client
(`hyper::client::conn::http2::handshake`), and the connector runs the
HTTP/2 server (`hyper::server::conn::http2::Builder::serve_connection`).
QUIC with the same split follows in M3.

## Consequences

- Per-stream flow control, `RST_STREAM` isolation, header-list limits and
  stream-count limits come from `h2`, which is widely deployed and fuzzed,
  not from code written here.
- The only parser Tunnelward owns before identity is known is the
  register frame: bounded to 64 KiB, length-checked before reading, fuzzed
  (`fuzz/fuzz_targets/decode.rs`) and run under Miri.
- Role reversal on one stream is unusual. v0.0.4 spikes it before anything
  is built on top; the fallback is HTTP/2 extended CONNECT (RFC 8441).
