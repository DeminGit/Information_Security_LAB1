package ru.demin.securenotes;

import java.time.Duration;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    public static final String ISSUER = "secure-notes";
    public static final String AUDIENCE = "secure-notes-api";

    @Bean
    PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(12); }

    @Bean
    SecretKeySpec jwtKey(@Value("${app.jwt-secret}") String encoded) {
        byte[] key = Base64.getDecoder().decode(encoded);
        if (key.length < 32) { throw new IllegalArgumentException("JWT_SECRET must contain at least 32 random bytes (Base64)"); }
        return new SecretKeySpec(key, "HmacSHA256");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKeySpec key) {
        return new NimbusJwtEncoder(new com.nimbusds.jose.jwk.source.ImmutableSecret<>(key));
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKeySpec key) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        OAuth2TokenValidator<Jwt> claims = jwt -> {
            boolean valid = jwt.getAudience().contains(AUDIENCE) && jwt.getExpiresAt() != null
                    && jwt.getIssuedAt() != null && jwt.getNotBefore() != null
                    && jwt.getSubject() != null && jwt.getSubject().matches("[1-9][0-9]{0,17}");
            return valid ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Invalid token claims", null));
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(Duration.ZERO), new JwtIssuerValidator(ISSUER), claims));
        return decoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // No cookie authentication: credentials are supplied explicitly in Authorization.
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/data").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/data").authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults())
                        .authenticationEntryPoint((req, res, ex) -> Errors.write(res, 401, "unauthorized")))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((req, res, ex) -> Errors.write(res, 401, "unauthorized"))
                        .accessDeniedHandler((req, res, ex) -> Errors.write(res, 403, "forbidden")))
                .headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'")))
                .addFilterBefore(new RequestLimits(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
