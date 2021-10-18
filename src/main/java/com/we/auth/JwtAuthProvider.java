package com.we.auth;

import com.we.auth.models.ExtendedUser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtAuthProvider implements AuthenticationProvider {

    @Value("${our.secret.signing.key}") String signingKey;

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException
    {
        JwtAuthentication ja = (JwtAuthentication) authentication;
        try {
            ja.claims = Jwts.parser()
                    .setSigningKey(signingKey)
                    .parseClaimsJws(ja.jwtAsString)
                    .getBody();
            ja.extUser = new ExtendedUser();
            ja.extUser.setId((String) ja.claims.get("id"));
            ja.extUser.setEmail((String) ja.claims.get("email"));
            ja.extUser.setPassword("");
            boolean subExists = ja.claims.get("subExists", Boolean.class);
            ja.extUser.setSubscribed(subExists);
            if (subExists) {
                Long subEnd = ja.claims.get("subEnd", Long.class);
                String subPlan = (String) ja.claims.get("subPlan");
                ja.extUser.setSubscribed(true);
                ja.extUser.setSubscriptionEnd(new Date(subEnd));
                ja.extUser.setSubscriptionPlan(subPlan);
            }
            ja.setAuthenticated(true);
        }
        catch (Exception e) {
            ja.setAuthenticated(false);
        }
        if (!ja.isAuthenticated())
            throw new BadCredentialsException("Authentication error !");
        return authentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(JwtAuthentication.class);
    }
}
