package com.we.auth;

import com.we.auth.models.ExtendedUser;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;


public class JwtAuthentication implements Authentication {

    String jwtAsString;
    boolean auth = false;
    ExtendedUser extUser;

    public Claims claims;

    public JwtAuthentication(String jwtAsString) {
        this.jwtAsString = jwtAsString;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // TODO: Add authorities
        return new HashSet<>();
    }

    @Override
    public String getCredentials() {
        return jwtAsString;
    }

    @Override
    public ExtendedUser getPrincipal() {
        return extUser;
    }

    @Override
    public Claims getDetails() {
        return claims;
    }

    @Override
    public boolean isAuthenticated() {
        return auth;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) {
        auth = isAuthenticated;
    }

    @Override
    public String getName() {
        return extUser.getEmail();
    }
}
