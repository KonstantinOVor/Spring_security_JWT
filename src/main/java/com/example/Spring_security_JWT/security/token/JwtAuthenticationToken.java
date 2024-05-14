package com.example.Spring_security_JWT.security.token;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
@Getter
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final UserDetails principal;
    private final String token;

    public JwtAuthenticationToken(UserDetails principal, String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.token = token;
        super.setAuthenticated(true);
    }
    public JwtAuthenticationToken(UserDetails principal, String token) {
        super(null);
        this.principal = principal;
        this.token = token;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public UserDetails getPrincipal() {
        return principal;
    }
}