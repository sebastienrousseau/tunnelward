// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

package io.github.sebastienrousseau.tunnelward.testcontainers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.ContainerLaunchException;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

class TunnelwardContainersTest {

    private static final DockerImageName IMAGE = DockerImageName.parse(
            System.getProperty("tunnelward.image", "ghcr.io/sebastienrousseau/tunnelward:0.0.21"));

    /** Each container's output in the test log, prefixed with its name. */
    private static Slf4jLogConsumer log(String name) {
        return new Slf4jLogConsumer(LoggerFactory.getLogger(name));
    }

    /** A service that answers every request with one line. */
    private static GenericContainer<?> service(TunnelwardGatewayContainer gateway) {
        return new GenericContainer<>(DockerImageName.parse("hashicorp/http-echo:1.0"))
                .withCommand("-text=hello-from-behind-the-firewall")
                .withNetwork(gateway.getNetwork())
                .withNetworkAliases("service")
                .waitingFor(Wait.forLogMessage("(?s).*server is listening.*", 1));
    }

    @Test
    void anAgentReachesTheServiceThroughTheGatewayAndConnector() throws Exception {
        try (var gateway = new TunnelwardGatewayContainer(IMAGE).withLogConsumer(log("gateway"));
             var service = service(gateway);
             var connector = new TunnelwardConnectorContainer(IMAGE)
                     .withGateway(gateway)
                     .withTarget("http://service:5678")
                     .withLogConsumer(log("connector"))) {
            gateway.start();
            service.start();
            connector.start();
            HttpResponse<String> answer = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(gateway.getAgentsUrl() + "/anything"))
                            .timeout(Duration.ofSeconds(10))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, answer.statusCode(), answer.body());
            assertTrue(answer.body().contains("hello-from-behind-the-firewall"), answer.body());
        }
    }

    @Test
    void aGatewayRefusingTheConnectorsSourceNeverServesIt() {
        // A container that fails to start is removed: keep its output.
        var output = new ToStringConsumer();
        try (var gateway = new TunnelwardGatewayContainer(IMAGE)
                     .withGatewayConfig("[connectors]\nallow = [\"192.0.2.0/24\"]\n")
                     .withLogConsumer(log("gateway"));
             var connector = new TunnelwardConnectorContainer(IMAGE)
                     .withGateway(gateway)
                     .withTarget("http://service:5678")
                     .withLogConsumer(log("connector"))
                     .withLogConsumer(output)
                     .waitingFor(Wait.forLogMessage("(?s).*Registered.*", 1)
                             .withStartupTimeout(Duration.ofSeconds(15)))) {
            gateway.start();
            assertThrows(ContainerLaunchException.class, connector::start);
            // The gateway drops a source outside its allowlist before TLS.
            String logs = output.toUtf8String();
            assertTrue(logs.contains("Failed") && !logs.contains("Registered"), logs);
        }
    }
}
