package com.hengtiansoft.imonitor.web.security.jwt;

import com.hengtiansoft.imonitor.web.security.entity.token.TokenType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.io.Serial;
import java.util.ArrayList;

public class JwtTokenAuthenticationToken extends AbstractAuthenticationToken  {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;

    private final String token;

    private final TokenType tokenType;

    private JwtTokenAuthenticationToken(final Object principal, final String token, final TokenType tokenType) {
        super(new ArrayList<>());
        this.principal = principal;
        this.token = token;
        this.tokenType = tokenType;
    }

    @Override
    public Object getCredentials() {
        return this.token;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public static JwtTokenAuthenticationToken accessToken(Object principal, String token) {
        return new JwtTokenAuthenticationToken(principal, token, TokenType.ACCESS_TOKEN);
    }

    public static JwtTokenAuthenticationToken apiToken(Object principal, String token) {
        return new JwtTokenAuthenticationToken(principal, token, TokenType.API_TOKEN);
    }

    public TokenType getTokenType() {return this.tokenType;}
}
