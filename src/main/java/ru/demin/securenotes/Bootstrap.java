package ru.demin.securenotes;

import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class Bootstrap implements ApplicationRunner {
    private final Database database;
    private final PasswordEncoder encoder;
    private final String username;
    private final String password;

    public Bootstrap(Database database, PasswordEncoder encoder,
                     @Value("${app.bootstrap-username}") String username,
                     @Value("${app.bootstrap-password}") String password) {
        this.database = database; this.encoder = encoder; this.username = username; this.password = password;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!username.matches("[a-zA-Z0-9_.-]{3,50}") || password.length() < 12
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("Bootstrap requires a valid username and a password of 12+ characters, at most 72 UTF-8 bytes");
        }
        if (database.findUser(username).isEmpty()) { database.createUser(username, encoder.encode(password)); }
    }
}
