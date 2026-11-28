// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

package io.github.sebastienrousseau.tunnelward.blind;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The agent side of the interop check (crates/tw-mcp/tests/sdk_interop.rs),
 * run with {@code java Interop.java <public key, base64url>}: reads a
 * tools/call, seals it, prints it; then reads the sealed answer and
 * prints it opened. It reads only the shapes that test writes, with
 * string matching: a real client uses its own JSON library.
 */
final class Interop {
  private Interop() {}

  public static void main(String[] args) throws Exception {
    byte[] publicKey = Base64.getUrlDecoder().decode(args[0]);
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    String call = in.readLine();
    String tool = group(call, "\"name\":\"([^\"]+)\"");
    String arguments = object(call, "\"arguments\":");
    TunnelwardBlind.Sealed sealed = TunnelwardBlind.seal(publicKey, tool, arguments);
    System.out.println(call.replace("\"arguments\":" + arguments, "\"arguments\":" + sealed.arguments()));
    System.out.flush();
    String answer = in.readLine();
    String inner = TunnelwardBlind.open(sealed.responseKey(), group(answer, "\"ct\":\"([^\"]+)\""));
    String id = group(answer, "\"id\":([0-9]+)");
    System.out.println("{\"jsonrpc\":\"2.0\",\"id\":" + id + "," + inner.substring(1));
  }

  private static String group(String text, String pattern) {
    Matcher m = Pattern.compile(pattern).matcher(text);
    if (!m.find()) {
      throw new IllegalArgumentException("no " + pattern);
    }
    return m.group(1);
  }

  /** The JSON object after {@code key}, by brace counting (no braces in strings). */
  private static String object(String text, String key) {
    int start = text.indexOf(key) + key.length();
    int depth = 0;
    for (int i = start; i < text.length(); i++) {
      depth += text.charAt(i) == '{' ? 1 : text.charAt(i) == '}' ? -1 : 0;
      if (depth == 0) {
        return text.substring(start, i + 1);
      }
    }
    throw new IllegalArgumentException("unbalanced object");
  }
}
