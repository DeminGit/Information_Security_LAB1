package ru.demin.securenotes;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
public class ApiController {
    private final Database database;
    private final PasswordEncoder passwords;
    private final JwtEncoder tokens;
    private final String dummyHash;

    public ApiController(Database database, PasswordEncoder passwords, JwtEncoder tokens) {
        this.database = database; this.passwords = passwords; this.tokens = tokens;
        this.dummyHash = passwords.encode(UUID.randomUUID().toString());
    }

    public record Login(@NotBlank @Size(max = 50) String username,
                        @NotBlank @Size(max = 72) String password) {
        @Override public String toString() { return "Login[redacted]"; }
    }
    public record Token(String accessToken, String tokenType, long expiresIn) {
        @Override public String toString() { return "Token[redacted]"; }
    }
    public record NewNote(@NotBlank @Size(max = 120) String title,
                          @NotBlank @Size(max = 2000) String content) { }
    public record NoteResponse(long id, String title, String content, OffsetDateTime createdAt) {
        static NoteResponse from(Database.Note note) {
            return new NoteResponse(note.id(), HtmlUtils.htmlEscape(note.title(), "UTF-8"),
                    HtmlUtils.htmlEscape(note.content(), "UTF-8"), note.createdAt());
        }
    }

    @PostMapping(value = "/auth/login", consumes = "application/json", produces = "application/json")
    public Token login(@Valid @RequestBody Login request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        var user = database.findUser(request.username());
        boolean matches = passwords.matches(request.password(), user.map(Database.User::passwordHash).orElse(dummyHash));
        if (user.isEmpty() || !matches) { throw new ResponseStatusException(HttpStatus.UNAUTHORIZED); }
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(SecurityConfig.ISSUER)
                .audience(List.of(SecurityConfig.AUDIENCE)).subject(Long.toString(user.orElseThrow().id()))
                .issuedAt(now).notBefore(now).expiresAt(now.plusSeconds(900)).id(UUID.randomUUID().toString()).build();
        String token = tokens.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        return new Token(token, "Bearer", 900);
    }

    @GetMapping(value = "/api/data", produces = "application/json")
    public List<NoteResponse> data(@AuthenticationPrincipal Jwt jwt,
                                  @RequestParam(defaultValue = "20") @Min(1) @Max(100) int limit,
                                  @RequestParam(defaultValue = "9223372036854775807") @Min(1) long before) {
        return database.notes(Long.parseLong(jwt.getSubject()), limit, before).stream().map(NoteResponse::from).toList();
    }

    @PostMapping(value = "/api/data", consumes = "application/json", produces = "application/json")
    @ResponseStatus(HttpStatus.CREATED)
    public NoteResponse create(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody NewNote request) {
        return NoteResponse.from(database.createNote(Long.parseLong(jwt.getSubject()), request.title(), request.content()));
    }
}
