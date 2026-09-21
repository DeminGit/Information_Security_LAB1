package ru.demin.securenotes;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class Database {
    private final JdbcClient jdbc;

    public Database(JdbcClient jdbc) { this.jdbc = jdbc; }

    public record User(long id, String username, String passwordHash) {
        @Override public String toString() { return "User[id=" + id + "]"; }
    }
    public record Note(long id, String title, String content, OffsetDateTime createdAt) { }

    public Optional<User> findUser(String username) {
        return jdbc.sql("SELECT id, username, password_hash FROM app_users WHERE username = :username")
                .param("username", username).query(User.class).optional();
    }

    public void createUser(String username, String hash) {
        jdbc.sql("INSERT INTO app_users(username, password_hash) VALUES (:username, :hash) ON CONFLICT (username) DO NOTHING")
                .param("username", username).param("hash", hash).update();
    }

    public List<Note> notes(long owner, int limit, long before) {
        return jdbc.sql("SELECT id, title, content, created_at FROM notes WHERE owner_id = :owner AND id < :before ORDER BY id DESC LIMIT :limit")
                .param("owner", owner).param("before", before).param("limit", limit).query(Note.class).list();
    }

    public Note createNote(long owner, String title, String content) {
        return jdbc.sql("INSERT INTO notes(owner_id, title, content) VALUES (:owner, :title, :content) RETURNING id, title, content, created_at")
                .param("owner", owner).param("title", title).param("content", content).query(Note.class).single();
    }
}
