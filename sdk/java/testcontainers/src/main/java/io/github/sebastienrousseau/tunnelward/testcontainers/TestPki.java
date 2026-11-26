// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

package io.github.sebastienrousseau.tunnelward.testcontainers;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * A throwaway certificate authority, valid for a day, that issues the
 * gateway's server certificate and connectors' X.509-SVIDs. For tests
 * only: nothing here is fit to protect real traffic.
 */
public final class TestPki {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeyPair caKey;
    private final X509CertificateHolder ca;

    /** A certificate and its private key, as PEM. */
    public record Issued(String certificatePem, String privateKeyPem) {}

    private TestPki(KeyPair caKey, X509CertificateHolder ca) {
        this.caKey = caKey;
        this.ca = ca;
    }

    /** A fresh authority with a P-256 key. */
    public static TestPki generate() {
        KeyPair key = keyPair();
        X500Name name = new X500Name("CN=Tunnelward test CA");
        X509CertificateHolder ca = sign(name, name, key, key, builder -> {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        });
        return new TestPki(key, ca);
    }

    /** The authority's certificate, as PEM. */
    public String caPem() {
        return pem("CERTIFICATE", encoded(ca));
    }

    /** A server certificate for {@code dnsName}. */
    public Issued server(String dnsName) {
        return leaf(dnsName, new GeneralName(GeneralName.dNSName, dnsName),
                KeyPurposeId.id_kp_serverAuth);
    }

    /** An X.509-SVID naming {@code spiffeId}, for a connector. */
    public Issued svid(String spiffeId) {
        return leaf("connector", new GeneralName(GeneralName.uniformResourceIdentifier, spiffeId),
                KeyPurposeId.id_kp_clientAuth);
    }

    private Issued leaf(String cn, GeneralName san, KeyPurposeId purpose) {
        KeyPair key = keyPair();
        X509CertificateHolder cert = sign(ca.getSubject(), new X500Name("CN=" + cn), caKey, key, leaf -> {
            leaf.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            leaf.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            leaf.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
            leaf.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san));
        });
        return new Issued(pem("CERTIFICATE", encoded(cert)),
                pem("PRIVATE KEY", key.getPrivate().getEncoded()));
    }

    @FunctionalInterface
    private interface Extensions {
        void add(JcaX509v3CertificateBuilder builder) throws IOException;
    }

    private static X509CertificateHolder sign(X500Name issuer, X500Name subject, KeyPair signer,
            KeyPair subjectKey, Extensions extensions) {
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(issuer, new BigInteger(64, RANDOM).add(BigInteger.ONE),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                subject, subjectKey.getPublic());
        try {
            extensions.add(builder);
            return builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("cannot sign a test certificate", e);
        }
    }

    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("no P-256 key generator", e);
        }
    }

    private static byte[] encoded(X509CertificateHolder cert) {
        try {
            return cert.getEncoded();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String pem(String type, byte[] der) {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(new PemObject(type, der));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toString();
    }
}
