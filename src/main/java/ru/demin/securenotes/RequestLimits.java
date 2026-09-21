package ru.demin.securenotes;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.filter.OncePerRequestFilter;

/** Single-instance lab limiter. Never trust client-supplied X-Forwarded-For. */
public class RequestLimits extends OncePerRequestFilter {
    private final Map<String, Integer> attempts = new HashMap<>();
    private long window = -1;

    private synchronized boolean allowed(String address) {
        long current = Instant.now().getEpochSecond() / 60;
        if (window != current) { attempts.clear(); window = current; }
        if (!attempts.containsKey(address) && attempts.size() >= 10_000) { return false; }
        int count = attempts.getOrDefault(address, 0);
        if (count >= 10) { return false; }
        attempts.put(address, count + 1);
        return true;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if ("POST".equals(request.getMethod())) {
            // Reject streaming bodies: a known, bounded Content-Length is required by this API.
            long length = request.getContentLengthLong();
            if (length < 0) { Errors.write(response, 411, "length_required"); return; }
            if (length > 16_384) { Errors.write(response, 413, "payload_too_large"); return; }
        }
        if ("/auth/login".equals(request.getServletPath()) && "POST".equals(request.getMethod())
                && !allowed(request.getRemoteAddr())) {
            response.setHeader("Retry-After", Long.toString(60 - Instant.now().getEpochSecond() % 60));
            Errors.write(response, 429, "too_many_requests");
            return;
        }
        chain.doFilter(request, response);
    }
}
