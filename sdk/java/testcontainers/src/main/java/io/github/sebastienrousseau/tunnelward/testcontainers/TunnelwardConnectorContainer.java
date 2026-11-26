// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

package io.github.sebastienrousseau.tunnelward.testcontainers;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

/**
 * A Tunnelward connector in front of a service on the gateway's network:
 * it dials out to a {@link TunnelwardGatewayContainer}, registers its
 * routes with an X.509-SVID the gateway's {@link TestPki} issues, and
 * forwards requests to {@link #withTarget(String) the target}. It is
 * ready once the gateway has accepted the registration.
 */
public final class TunnelwardConnectorContainer extends GenericContainer<TunnelwardConnectorContainer> {

    private static final String DIR = "/etc/tunnelward/";

    private TunnelwardGatewayContainer gateway;
    private String spiffeId = "spiffe://example.org/connector";
    private List<String> routes = List.of("*");
    private String target;

    /** A connector run from {@code image}. */
    public TunnelwardConnectorContainer(DockerImageName image) {
        super(image);
        waitingFor(Wait.forLogMessage("(?s).*Registered.*", 1).withStartupTimeout(Duration.ofSeconds(60)));
    }

    /** Dials {@code gateway}, joining its network and starting after it. */
    public TunnelwardConnectorContainer withGateway(TunnelwardGatewayContainer gateway) {
        this.gateway = gateway;
        withNetwork(gateway.getNetwork());
        dependsOn(gateway);
        return self();
    }

    /** The SPIFFE ID in the connector's SVID (default {@code spiffe://example.org/connector}). */
    public TunnelwardConnectorContainer withSpiffeId(String spiffeId) {
        this.spiffeId = spiffeId;
        return self();
    }

    /** The routes to register (default {@code *}, every request). */
    public TunnelwardConnectorContainer withRoutes(String... routes) {
        this.routes = List.of(routes);
        return self();
    }

    /** The service to forward to, such as {@code http://mcp-server:8080}. */
    public TunnelwardConnectorContainer withTarget(String url) {
        this.target = url;
        return self();
    }

    /** The connector file this container runs. */
    public String connectorConfig() {
        String quoted = routes.stream().map(r -> "\"" + r + "\"").collect(Collectors.joining(", "));
        return """
                [gateway]
                address = "%s:%d"
                server_name = "%s"
                ca = "%sca.crt"

                [identity]
                spiffe_id = "%s"
                cert = "%sconnector.crt"
                key = "%sconnector.key"

                [register]
                routes = [%s]

                [target]
                url = "%s"
                """.formatted(TunnelwardGatewayContainer.SERVER_NAME,
                TunnelwardGatewayContainer.CONNECTORS_PORT, TunnelwardGatewayContainer.SERVER_NAME,
                DIR, spiffeId, DIR, DIR, quoted, target);
    }

    @Override
    protected void configure() {
        Objects.requireNonNull(gateway, "withGateway: the connector needs a gateway");
        Objects.requireNonNull(target, "withTarget: the connector needs a service to forward to");
        TestPki pki = gateway.getPki();
        TestPki.Issued svid = pki.svid(spiffeId);
        copy(svid.certificatePem(), "connector.crt");
        copy(svid.privateKeyPem(), "connector.key");
        copy(pki.caPem(), "ca.crt");
        copy(connectorConfig(), "connector.toml");
        withCommand("connector", "--config", DIR + "connector.toml");
    }

    private void copy(String text, String name) {
        withCopyToContainer(Transferable.of(text.getBytes(StandardCharsets.UTF_8), 0644), DIR + name);
    }
}
