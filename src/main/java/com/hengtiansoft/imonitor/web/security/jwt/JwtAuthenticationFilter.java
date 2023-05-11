package com.hengtiansoft.imonitor.web.security.jwt;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.lang.Assert;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private JwtProvider jwtProvider;

    public JwtAuthenticationFilter() {
        super("/**");
    }

    public JwtAuthenticationFilter(String filterProcessUrl) {
        super(filterProcessUrl);
    }

    public void afterPropertiesSet() {
        Assert.notNull(this.jwtProvider, "JwtProvider must not be null.");
    }

    @Override
    protected boolean requiresAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) {
        if (request.getServletPath().contains("/backend/v1/auth")) {
            return false;
        }

        final String authHeader = request.getHeader("Authorization");
        return authHeader != null;
    }

    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        try {
            String token = obtainToken(request);
            String username = jwtProvider.extractUsername(token);
            JwtTokenAuthenticationToken jwtTokenAuthenticationToken = new JwtTokenAuthenticationToken(username, token);
            jwtTokenAuthenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
            return this.getAuthenticationManager().authenticate(jwtTokenAuthenticationToken);
        } catch (JwtException ex) {
            throw new BadCredentialsException(ex.getMessage(), ex);
        }
    }

    @Override
    protected final void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authResult)
            throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authResult);
        SecurityContextHolder.setContext(context);
        chain.doFilter(request, response);
    }

    private String obtainToken(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");
        if (!authHeader.startsWith("Bearer ")) {
            throw new BadCredentialsException("Invalid token.");
        }

        return request.getHeader("Authorization").substring(7);
    }

    public void setJwtProvider(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }
}
