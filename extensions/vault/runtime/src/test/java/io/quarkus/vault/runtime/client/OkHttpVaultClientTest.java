package io.quarkus.vault.runtime.client;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.Optional;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;

import io.quarkus.vault.runtime.LogConfidentialityLevel;
import io.quarkus.vault.runtime.client.dto.auth.VaultKubernetesAuth;
import io.quarkus.vault.runtime.config.*;

class OkHttpVaultClientTest {

    private static final int MOCK_SERVER_PORT = 8089;
    private static final WireMockServer wireMockServer = new WireMockServer(MOCK_SERVER_PORT);
    private static final String loginResponse = "{\n" +
            "  \"request_id\": \"0493dbdf-b07a-a6be-7b67-dc6d2f682fcd\",\n" +
            "  \"lease_id\": \"\",\n" +
            "  \"renewable\": false,\n" +
            "  \"lease_duration\": 0,\n" +
            "  \"data\": null,\n" +
            "  \"wrap_info\": null,\n" +
            "  \"warnings\": null,\n" +
            "  \"auth\": {\n" +
            "    \"client_token\": \"s.tmaYRmdXqKVF810aYOinWgMd\",\n" +
            "    \"accessor\": \"PAwVe79bWN0uoGCLrWdfYsIR\",\n" +
            "    \"policies\": [\n" +
            "      \"default\",\n" +
            "      \"mypolicy\"\n" +
            "    ],\n" +
            "    \"token_policies\": [\n" +
            "      \"default\",\n" +
            "      \"mypolicy\"\n" +
            "    ],\n" +
            "    \"metadata\": {\n" +
            "      \"username\": \"bob\"\n" +
            "    },\n" +
            "    \"lease_duration\": 604800,\n" +
            "    \"renewable\": true,\n" +
            "    \"entity_id\": \"939a217d-9172-0ba8-1b6a-7594213f1fad\",\n" +
            "    \"token_type\": \"service\",\n" +
            "    \"orphan\": true\n" +
            "  }\n" +
            "}\n";

    private static final ObjectMapper mapper = new ObjectMapper();

    @Test
    void loginKubernetes() throws IOException {
        final String configuredAuthPath = "kubernetes_custom";
        final VaultRuntimeConfig config = createConfig(configuredAuthPath);
        final OkHttpVaultClient client = new OkHttpVaultClient(config);

        wireMockServer.stubFor(
                post("/v1/auth/kubernetes_custom/login")
                        .withRequestBody(equalToJson("{ \"role\": \"some/role\", \"jwt\": \"/var/k8s/token\" }"))
                        .willReturn(aResponse().withBody(loginResponse)));

        final VaultKubernetesAuth vaultKubernetesAuth = client.loginKubernetes("some/role", "/var/k8s/token");

        assertThat(vaultKubernetesAuth)
                .usingRecursiveComparison()
                .isEqualTo(mapper.readValue(loginResponse, VaultKubernetesAuth.class));
    }

    @BeforeAll
    static void start() {
        mapper.configure(FAIL_ON_UNKNOWN_PROPERTIES, false);
        wireMockServer.start();
    }

    @AfterAll
    static void stop() {
        wireMockServer.stop();
    }

    private VaultRuntimeConfig createConfig(String authLoginPath) {
        try {
            final VaultKubernetesAuthenticationConfig kubernetesAuthConfig = new VaultKubernetesAuthenticationConfig();
            kubernetesAuthConfig.path = authLoginPath;

            VaultRuntimeConfig config = new VaultRuntimeConfig();
            config.tls = new VaultTlsConfig();
            config.authentication = new VaultAuthenticationConfig();
            config.authentication.kubernetes = kubernetesAuthConfig;
            config.authentication.appRole = new VaultAppRoleAuthenticationConfig();
            config.authentication.userpass = new VaultUserpassAuthenticationConfig();
            config.url = Optional.of(new URL("http://localhost:" + 8089));
            config.authentication.clientToken = Optional.empty();
            config.authentication.kubernetes.role = Optional.empty();
            config.authentication.appRole.roleId = Optional.empty();
            config.authentication.appRole.secretId = Optional.empty();
            config.authentication.userpass.username = Optional.of("bob");
            config.authentication.userpass.password = Optional.of("sinclair");
            config.connectTimeout = Duration.ofSeconds(1);
            config.readTimeout = Duration.ofSeconds(1);
            config.tls.skipVerify = true;
            config.logConfidentialityLevel = LogConfidentialityLevel.LOW;
            config.renewGracePeriod = Duration.ofSeconds(3);
            return config;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

}
