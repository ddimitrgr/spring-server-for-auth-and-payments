package com.we.auth;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Component
public class JwtAuthFilter extends GenericFilterBean {

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws IOException, ServletException
    {
        final HttpServletRequest request = (HttpServletRequest) req;
        final String authHeader = request.getHeader("authorization");
        if (!"OPTIONS".equals(request.getMethod())
                && authHeader != null && authHeader.startsWith("Bearer ")
                && authHeader.length() > 7) {
            final String token = authHeader.substring(7);
            final JwtAuthentication auth = new JwtAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        chain.doFilter(req, res);
    }
}