package com.example.Spring_security_JWT.security.provider;

import com.example.Spring_security_JWT.security.token.JwtAuthenticationToken;
import com.example.Spring_security_JWT.security.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Collection;


@RequiredArgsConstructor
@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();
        UserDetails userDetails = getUserDetails(token);
        Collection<? extends GrantedAuthority> authorities = jwtUtil.getRolesFromToken(token).stream()
                .map(SimpleGrantedAuthority::new).toList();

        if (jwtUtil.validateToken(token, userDetails)) {
            return new JwtAuthenticationToken(userDetails, token, authorities);
        } else {
            throw new BadCredentialsException("Токен недействителен");
        }
    }

    public UserDetails getUserDetails(String token) {
        String username = extractUsernameFromToken(token);
        return userDetailsService.loadUserByUsername(username);
    }

    private String extractUsernameFromToken(String token) {
        return jwtUtil.getUsernameFromToken(token);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}