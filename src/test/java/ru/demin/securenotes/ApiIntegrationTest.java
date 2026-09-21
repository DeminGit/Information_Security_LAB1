package ru.demin.securenotes;

import java.net.URI;
import java.net.http.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ApiIntegrationTest {
    private static final String PASSWORD = randomSecret();
    private static final String KEY = randomSecret();
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    @LocalServerPort int port;
    @Autowired JdbcClient jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;
    private static String accessToken;

    private static String randomSecret() {
        byte[] bytes = new byte[32]; new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("debug", () -> "false");
        registry.add("spring.datasource.url", () -> System.getenv().getOrDefault("TEST_DB_URL", "jdbc:postgresql://localhost:55432/secure_notes_test"));
        registry.add("spring.datasource.username", () -> System.getenv().getOrDefault("TEST_DB_USER", "test_user"));
        registry.add("spring.datasource.password", () -> System.getenv("TEST_DB_PASSWORD"));
        registry.add("app.jwt-secret", () -> KEY);
        registry.add("app.bootstrap-username", () -> "student");
        registry.add("app.bootstrap-password", () -> PASSWORD);
    }

    private HttpResponse<String> request(String method, String path, Object body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
        if (token != null) { builder.header("Authorization", "Bearer " + token); }
        if (body != null) { builder.header("Content-Type", "application/json"); }
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        return HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test @Order(1)
    void loginReturnsJwtAndPasswordIsHashed() throws Exception {
        var response = request("POST", "/auth/login", Map.of("username", "student", "password", PASSWORD), null);
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode json = JSON.readTree(response.body());
        accessToken = json.get("accessToken").asString();
        assertThat(accessToken.split("\\.")).hasSize(3);
        assertThat(json.get("expiresIn").asInt()).isEqualTo(900);
        assertThat(response.headers().firstValue("Cache-Control").orElse("")).contains("no-store");
        String hash = jdbc.sql("SELECT password_hash FROM app_users WHERE username = 'student'").query(String.class).single();
        assertThat(hash).startsWith("$2a$12$").isNotEqualTo(PASSWORD);
        assertThat(passwords.matches(PASSWORD, hash)).isTrue();
    }

    @Test @Order(2)
    void protectedEndpointsRejectMissingAndMalformedTokens() throws Exception {
        assertThat(request("GET", "/api/data", null, null).statusCode()).isEqualTo(401);
        assertThat(request("POST", "/api/data", Map.of("title", "a", "content", "b"), null).statusCode()).isEqualTo(401);
        assertThat(request("GET", "/api/data", null, "not-a-jwt").statusCode()).isEqualTo(401);
        String[] pieces = accessToken.split("\\.");
        String signature = (pieces[2].startsWith("A") ? "B" : "A") + pieces[2].substring(1);
        assertThat(request("GET", "/api/data", null, pieces[0] + "." + pieces[1] + "." + signature).statusCode()).isEqualTo(401);
        assertThat(request("GET", "/api/data?access_token=" + accessToken, null, null).statusCode()).isEqualTo(401);
    }

    @Test @Order(3)
    void sqlInjectionDoesNotAuthenticateAndErrorsDoNotEnumerateUsers() throws Exception {
        var wrong = request("POST", "/auth/login", Map.of("username", "student", "password", "incorrect-password"), null);
        var injection = request("POST", "/auth/login", Map.of("username", "' OR '1'='1' --", "password", "incorrect-password"), null);
        assertThat(wrong.statusCode()).isEqualTo(401);
        assertThat(injection.statusCode()).isEqualTo(401);
        assertThat(injection.body()).isEqualTo(wrong.body()).doesNotContain("SELECT", "password_hash", "exception");
    }

    @Test @Order(4)
    void notesEscapeXssPreserveSqlTextAndAreIsolatedByOwner() throws Exception {
        String payload = "<script>alert('xss')</script>";
        String sql = "'); DROP TABLE app_users; --";
        var created = request("POST", "/api/data", Map.of("title", payload, "content", sql), accessToken);
        assertThat(created.statusCode()).isEqualTo(201);
        assertThat(created.body()).contains("&lt;script&gt;").doesNotContain("<script>", "password");
        assertThat(jdbc.sql("SELECT title FROM notes ORDER BY id DESC LIMIT 1").query(String.class).single()).isEqualTo(payload);
        assertThat(jdbc.sql("SELECT content FROM notes ORDER BY id DESC LIMIT 1").query(String.class).single()).isEqualTo(sql);
        var data = request("GET", "/api/data", null, accessToken);
        assertThat(data.statusCode()).isEqualTo(200);
        assertThat(data.body()).contains("&lt;script&gt;").doesNotContain("<script>");
        jdbc.sql("INSERT INTO app_users(username,password_hash) VALUES ('other', :hash)")
                .param("hash", passwords.encode(randomSecret())).update();
        long otherId = jdbc.sql("SELECT id FROM app_users WHERE username='other'").query(Long.class).single();
        String otherToken = token(Long.toString(otherId), SecurityConfig.ISSUER, SecurityConfig.AUDIENCE, Instant.now().plusSeconds(900));
        assertThat(request("GET", "/api/data", null, otherToken).body()).isEqualTo("[]");
    }

    private String token(String subject, String issuer, String audience, Instant expires) {
        var claims = JwtClaimsSet.builder().subject(subject).issuer(issuer).audience(List.of(audience))
                .issuedAt(Instant.now().minusSeconds(120)).notBefore(Instant.now().minusSeconds(120)).expiresAt(expires).build();
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
    }

    @Test @Order(5)
    void rejectsExpiredWrongIssuerWrongAudienceAndMissingExpiry() throws Exception {
        String owner = jdbc.sql("SELECT id FROM app_users WHERE username='student'").query(String.class).single();
        for (String invalid : List.of(
                token(owner, SecurityConfig.ISSUER, SecurityConfig.AUDIENCE, Instant.now().minusSeconds(10)),
                token(owner, "attacker", SecurityConfig.AUDIENCE, Instant.now().plusSeconds(900)),
                token(owner, SecurityConfig.ISSUER, "other-api", Instant.now().plusSeconds(900)),
                token("not-a-number", SecurityConfig.ISSUER, SecurityConfig.AUDIENCE, Instant.now().plusSeconds(900)))) {
            assertThat(request("GET", "/api/data", null, invalid).statusCode()).isEqualTo(401);
        }
        var noExpiry = JwtClaimsSet.builder().subject(owner).issuer(SecurityConfig.ISSUER)
                .audience(List.of(SecurityConfig.AUDIENCE)).issuedAt(Instant.now()).notBefore(Instant.now()).build();
        String invalid = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), noExpiry)).getTokenValue();
        assertThat(request("GET", "/api/data", null, invalid).statusCode()).isEqualTo(401);
    }

    @Test @Order(6)
    void validatesInputsAndBoundsPaginationAndBodySize() throws Exception {
        assertThat(request("POST", "/api/data", Map.of("title", " ", "content", "a"), accessToken).statusCode()).isEqualTo(400);
        assertThat(request("POST", "/api/data", Map.of("title", "a", "content", "b", "ownerId", 2), accessToken).statusCode()).isEqualTo(400);
        assertThat(request("POST", "/api/data", Map.of("title", "a", "content", "a".repeat(2001)), accessToken).statusCode()).isEqualTo(400);
        assertThat(request("GET", "/api/data?limit=101", null, accessToken).statusCode()).isEqualTo(400);
        assertThat(request("GET", "/api/data?before=0", null, accessToken).statusCode()).isEqualTo(400);
        assertThat(request("POST", "/api/data", Map.of("title", "a", "content", "a".repeat(17000)), accessToken).statusCode()).isEqualTo(413);
        assertThat(request("GET", "/api/data?limit=1", null, accessToken).statusCode()).isEqualTo(200);
    }

    @Test @Order(7)
    void securityHeadersAndNoSessionCookie() throws Exception {
        var response = request("GET", "/api/data", null, accessToken);
        assertThat(response.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
        assertThat(response.headers().firstValue("X-Frame-Options")).contains("DENY");
        assertThat(response.headers().firstValue("Content-Security-Policy").orElse("")).contains("default-src 'none'");
        assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(request("GET", "/unknown", null, accessToken).statusCode()).isEqualTo(403);
    }

    @Test @Order(99)
    void bruteForceIsRateLimited() throws Exception {
        boolean limited = false;
        // Allow a minute boundary during the test: 21 attempts span at most two short windows.
        for (int i = 0; i < 21; i++) {
            var response = request("POST", "/auth/login", Map.of("username", "student", "password", "wrong-password"), null);
            if (response.statusCode() == 429) {
                assertThat(response.headers().firstValue("Retry-After")).isPresent();
                limited = true; break;
            }
            assertThat(response.statusCode()).isEqualTo(401);
        }
        assertThat(limited).isTrue();
    }
}
