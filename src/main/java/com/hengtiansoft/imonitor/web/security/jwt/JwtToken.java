package com.hengtiansoft.imonitor.web.security.jwt;

import com.hengtiansoft.imonitor.web.security.entity.token.TokenType;

public interface JwtToken {

    String getTokenString();

    Object getPrincipal();

    TokenType getTokenType();

    boolean isRevoked();

    boolean isExpired();
}
