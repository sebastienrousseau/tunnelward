// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

package io.github.sebastienrousseau.tunnelward.testcontainers;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

/**
 * A Tunnelward gateway: connectors dial in on {@link #CONNECTORS_PORT}
 * with mutual TLS, agents connect to {@link #getAgentsUrl()} over plain
 * HTTP. Its certificate and the roots it trusts come from a
 * {@link TestPki}, which {@link TunnelwardConnectorContainer} uses too.
 *
 * <pre>{@code
 * var gateway = new TunnelwardGatewayContainer(image);
 * var connector = new TunnelwardConnectorContainer(image)
 *     .withGateway(gateway)
 *     .withTarget("http://mcp-server:8080");
 * }</pre>
 */
public final class TunnelwardGatewayContainer extends GenericContainer<TunnelwardGatewayContainer> {

    /** Where connectors dial in, inside the network. */
    public static final int CONNECTORS_PORT = 7443;
    /** Where agents connect. */
    public static final int AGENTS_PORT = 8443;
    /** The gateway's name on the network and in its certificate. */
    public static final String SERVER_NAME = "tunnelward-gateway";

    private static final String DIR = "/etc/tunnelward/";

    private final TestPki pki;
    private String extraConfig = "";

    /** A gateway with a fresh {@link TestPki}, on a network of its own. */
    public TunnelwardGatewayContainer(DockerImageName image) {
        this(image, TestPki.generate());
    }

    /** A gateway whose certificates {@code pki} issues. */
    public TunnelwardGatewayContainer(DockerImageName image, TestPki pki) {
        super(image);
        this.pki = pki;
        withNetwork(Network.newNetwork());
        withNetworkAliases(SERVER_NAME);
        withExposedPorts(CONNECTORS_PORT, AGENTS_PORT);
        waitingFor(Wait.forLogMessage("(?s).*agents on .*", 1).withStartupTimeout(Duration.ofSeconds(60)));
    }

    /**
     * TOML appended to the gateway file after {@code [listen]} and
     * {@code [tls]}: {@code [connectors]}, {@code [agents]},
     * {@code [policy]} and the rest.
     */
    public TunnelwardGatewayContainer withGatewayConfig(String toml) {
        this.extraConfig = toml;
        return self();
    }

    /** The authority behind the gateway's certificate and trusted roots. */
    public TestPki getPki() {
        return pki;
    }

    /** The agent ingress, from the host. */
    public String getAgentsUrl() {
        return "http://" + getHost() + ":" + getMappedPort(AGENTS_PORT);
    }

    /** The connector listener, from the host, as {@code host:port}. */
    public String getConnectorsAddress() {
        return getHost() + ":" + getMappedPort(CONNECTORS_PORT);
    }

    /** The gateway file this container runs. */
    public String gatewayConfig() {
        return """
                [listen]
                connectors = "0.0.0.0:%d"
                ingress = "0.0.0.0:%d"

                [tls]
                cert = "%sgateway.crt"
                key = "%sgateway.key"
                client_ca = "%sca.crt"

                %s
                """.formatted(CONNECTORS_PORT, AGENTS_PORT, DIR, DIR, DIR, extraConfig);
    }

    @Override
    protected void configure() {
        TestPki.Issued server = pki.server(SERVER_NAME);
        copy(server.certificatePem(), "gateway.crt");
        copy(server.privateKeyPem(), "gateway.key");
        copy(pki.caPem(), "ca.crt");
        copy(gatewayConfig(), "tunnelward.toml");
        withCommand("gateway", "--config", DIR + "tunnelward.toml");
    }

    private void copy(String text, String name) {
        withCopyToContainer(Transferable.of(text.getBytes(StandardCharsets.UTF_8), 0644), DIR + name);
    }
}
