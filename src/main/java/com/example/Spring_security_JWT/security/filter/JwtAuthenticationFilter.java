package com.example.Spring_security_JWT.security.filter;

import com.example.Spring_security_JWT.security.provider.JwtAuthenticationProvider;
import com.example.Spring_security_JWT.security.token.JwtAuthenticationToken;
import com.example.Spring_security_JWT.security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getRequestURI().equals("/api/login")) {
            filterChain.doFilter(request, response);
        } else {
        String token = extractTokenFromRequest(request);

        if (token != null && validateToken(token)) {
            Authentication authentication = createAuthentication(token);
            if (authentication == null) {
                log.debug("JWT токен недействителен");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "JWT токен недействителен");
            }
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            log.debug("JWT токен недействителен");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "JWT токен недействителен");
        }

        filterChain.doFilter(request, response);
        }
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {

        UserDetails userDetails = jwtAuthenticationProvider.getUserDetails(token);
        if (userDetails == null) {
            return false;
        }
        return jwtUtil.validateToken(token, userDetails);
    }

    private Authentication createAuthentication(String token) {
        UserDetails userDetails = jwtAuthenticationProvider.getUserDetails(token);
        if (userDetails != null) {
            JwtAuthenticationToken authentication = new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities());
            return jwtAuthenticationProvider.authenticate(authentication);
        }
        return null;
    }
}
