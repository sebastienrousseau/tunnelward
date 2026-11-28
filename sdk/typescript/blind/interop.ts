// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

// The agent side of the interop check (crates/tw-mcp/tests/sdk_interop.rs):
// reads a tools/call, seals it to the X-Wing key in argv[2], prints it;
// then reads the connector's sealed answer and prints it opened. One
// JSON document per line.

import { createInterface } from "node:readline";
import { fromBase64url, openAnswer, sealCall } from "./blind.ts";
import { nodeProvider } from "./node.ts";

const publicKey = fromBase64url(process.argv[2] ?? "");
const reader = createInterface({ input: process.stdin });
const lines = reader[Symbol.asyncIterator]();

const call = (await lines.next()).value as string;
const { body, responseKey } = await sealCall(call, publicKey, nodeProvider);
console.log(body);
const answer = (await lines.next()).value as string;
console.log(await openAnswer(answer, responseKey));
reader.close();
