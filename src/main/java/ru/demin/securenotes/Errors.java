package ru.demin.securenotes;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.ErrorResponse;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import tools.jackson.databind.json.JsonMapper;

@RestControllerAdvice
public class Errors {
    private static final Logger LOG = LoggerFactory.getLogger(Errors.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    public static void write(HttpServletResponse response, int status, String code) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        if (status == 401) { response.setHeader("WWW-Authenticate", "Bearer"); }
        response.getOutputStream().write(JSON.writeValueAsBytes(Map.of("error", code)));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, String>> handle(Exception exception) {
        int status = exception instanceof ErrorResponse error ? error.getStatusCode().value() : 500;
        if (exception instanceof HttpMessageNotReadableException
                || exception instanceof MethodArgumentTypeMismatchException) { status = 400; }
        if (status >= 500) { LOG.error("Request failed: {}", exception.getClass().getSimpleName()); }
        String code = switch (status) {
            case 400 -> "invalid_request";
            case 401 -> "unauthorized";
            case 403 -> "forbidden";
            case 404 -> "not_found";
            case 405 -> "method_not_allowed";
            case 415 -> "unsupported_media_type";
            default -> "request_failed";
        };
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
}
