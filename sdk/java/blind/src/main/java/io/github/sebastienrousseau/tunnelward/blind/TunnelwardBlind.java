// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

package io.github.sebastienrousseau.tunnelward.blind;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Tunnelward gateway-blind mode, agent side (ADR 0016, experimental), on
 * the JDK alone (25 or later: ML-KEM arrived in JDK 24).
 *
 * <p>{@link #seal} seals a {@code tools/call}'s arguments to a
 * connector's X-Wing public key with HPKE (RFC 9180: X-Wing, HKDF-SHA256,
 * AES-256-GCM) and returns the {@code arguments} object to send in their
 * place; {@link #open} opens the sealed answer. The JDK has no JSON
 * parser, so the caller's MCP client builds and reads the JSON-RPC
 * envelope with its own. Get the connector's public key from its
 * operator, never through the gateway.
 */
public final class TunnelwardBlind {
  private static final byte[] INFO = bytes("tunnelward blind v1");
  private static final byte[] RESPONSE = bytes("tunnelward blind response");
  private static final byte[] LABEL = bytes("\\.//^\\");
  private static final int ML_KEM_PUBLIC = 1184;
  /** HPKE suite id: X-Wing (0x647a), HKDF-SHA256 (1), AES-256-GCM (2). */
  private static final byte[] SUITE = concat(bytes("HPKE"), new byte[] {0x64, 0x7a, 0, 1, 0, 2});
  /** SubjectPublicKeyInfo headers: ML-KEM-768 (FIPS 203) and X25519. */
  private static final byte[] ML_KEM_SPKI = {
    0x30, (byte) 0x82, 0x04, (byte) 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x04, 0x02, 0x03, (byte) 0x82, 0x04, (byte) 0xa1, 0x00
  };
  private static final byte[] X25519_SPKI = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};

  private TunnelwardBlind() {}

  /** Opens one call's answer. */
  public static final class ResponseKey {
    private final byte[] key;

    private ResponseKey(byte[] key) {
      this.key = key;
    }
  }

  /** A sealed call: the arguments object to send, and the key for its answer. */
  public record Sealed(String arguments, ResponseKey responseKey) {}

  /**
   * Seals {@code argumentsJson}, the JSON of a {@code tools/call}'s
   * arguments, to the connector's X-Wing {@code publicKey}, bound to
   * {@code toolName}.
   *
   * @return the {@code arguments} object to put in the call, and the key
   *     that opens its answer
   * @throws GeneralSecurityException if the key is not an X-Wing key
   */
  public static Sealed seal(byte[] publicKey, String toolName, String argumentsJson)
      throws GeneralSecurityException {
    byte[][] kem = encapsulate(publicKey);
    byte[] enc = kem[0];
    byte[] shared = kem[1];
    byte[][] schedule = keySchedule(shared);
    byte[] aad = concat(bytes("tools/call\0"), bytes(toolName));
    byte[] ct = aesGcm(Cipher.ENCRYPT_MODE, schedule[0], schedule[1], aad, bytes(argumentsJson));
    byte[] responseKey = labeledExpand(schedule[2], "sec", RESPONSE, 32);
    String arguments =
        "{\"tw_blind\":{\"v\":1,\"enc\":\"" + base64url(enc) + "\",\"ct\":\"" + base64url(ct) + "\"}}";
    return new Sealed(arguments, new ResponseKey(responseKey));
  }

  /**
   * Opens the {@code ct} of an answer's {@code result.tw_blind}.
   *
   * @return the answer's {@code {"result": ...}} or {@code {"error": ...}}
   * @throws GeneralSecurityException if it does not open
   */
  public static String open(ResponseKey key, String ct) throws GeneralSecurityException {
    byte[] plain = aesGcm(Cipher.DECRYPT_MODE, key.key, new byte[12], RESPONSE, Base64.getUrlDecoder().decode(ct));
    return new String(plain, StandardCharsets.UTF_8);
  }

  /** X-Wing Encapsulate (draft-connolly-cfrg-xwing-kem-11): {ct, ss}. */
  private static byte[][] encapsulate(byte[] publicKey) throws GeneralSecurityException {
    if (publicKey.length != ML_KEM_PUBLIC + 32 || !mlKemPublicOk(publicKey)) {
      throw new GeneralSecurityException("not an X-Wing public key");
    }
    byte[] pkM = Arrays.copyOf(publicKey, ML_KEM_PUBLIC);
    byte[] pkX = Arrays.copyOfRange(publicKey, ML_KEM_PUBLIC, publicKey.length);
    PublicKey mlKem = KeyFactory.getInstance("ML-KEM").generatePublic(new X509EncodedKeySpec(concat(ML_KEM_SPKI, pkM)));
    KEM.Encapsulated m = KEM.getInstance("ML-KEM").newEncapsulator(mlKem).encapsulate();
    KeyPair ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair();
    byte[] spki = ephemeral.getPublic().getEncoded();
    byte[] ctX = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    PublicKey peer = KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI, pkX)));
    KeyAgreement agreement = KeyAgreement.getInstance("X25519");
    agreement.init(ephemeral.getPrivate());
    agreement.doPhase(peer, true);
    byte[] ssX = agreement.generateSecret();
    byte[] ss = MessageDigest.getInstance("SHA3-256").digest(concat(m.key().getEncoded(), ssX, ctX, pkX, LABEL));
    return new byte[][] {concat(m.encapsulation(), ctX), ss};
  }

  /** FIPS 203's encapsulation key check: every coefficient below q. */
  private static boolean mlKemPublicOk(byte[] pk) {
    for (int i = 0; i + 2 < ML_KEM_PUBLIC - 32; i += 3) {
      int first = (pk[i] & 0xff) | ((pk[i + 1] & 0x0f) << 8);
      int second = ((pk[i + 1] & 0xff) >> 4) | ((pk[i + 2] & 0xff) << 4);
      if (first >= 3329 || second >= 3329) {
        return false;
      }
    }
    return true;
  }

  /** HPKE base-mode KeySchedule: {key, base nonce, exporter secret}. */
  private static byte[][] keySchedule(byte[] shared) throws GeneralSecurityException {
    byte[] pskIdHash = labeledExtract(new byte[0], "psk_id_hash", new byte[0]);
    byte[] infoHash = labeledExtract(new byte[0], "info_hash", INFO);
    byte[] context = concat(new byte[] {0}, pskIdHash, infoHash);
    byte[] secret = labeledExtract(shared, "secret", new byte[0]);
    return new byte[][] {
      labeledExpand(secret, "key", context, 32),
      labeledExpand(secret, "base_nonce", context, 12),
      labeledExpand(secret, "exp", context, 32)
    };
  }

  private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
    Mac mac = Mac.getInstance("HmacSHA256");
    // The JDK refuses an empty key; HMAC pads short keys with zeros, so
    // 32 zero bytes is the same key.
    mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
    return mac.doFinal(data);
  }

  private static byte[] labeledExtract(byte[] salt, String label, byte[] ikm) throws GeneralSecurityException {
    return hmac(salt, concat(bytes("HPKE-v1"), SUITE, bytes(label), ikm));
  }

  /** HKDF-Expand (RFC 5869) with HPKE's label. */
  private static byte[] labeledExpand(byte[] prk, String label, byte[] info, int length)
      throws GeneralSecurityException {
    byte[] labeled = concat(new byte[] {(byte) (length >> 8), (byte) length}, bytes("HPKE-v1"), SUITE, bytes(label), info);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] block = new byte[0];
    for (int i = 1; out.size() < length; i++) {
      block = hmac(prk, concat(block, labeled, new byte[] {(byte) i}));
      out.writeBytes(block);
    }
    return Arrays.copyOf(out.toByteArray(), length);
  }

  private static byte[] aesGcm(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] data)
      throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
    cipher.updateAAD(aad);
    return cipher.doFinal(data);
  }

  private static String base64url(byte[] data) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
  }

  private static byte[] bytes(String text) {
    return text.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] p : parts) {
      out.writeBytes(p);
    }
    return out.toByteArray();
  }
}
