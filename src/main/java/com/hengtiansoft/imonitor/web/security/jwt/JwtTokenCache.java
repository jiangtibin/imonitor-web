package com.hengtiansoft.imonitor.web.security.jwt;

public interface JwtTokenCache {

    JwtAuthenticationToken getByJwtToken(String jwt);

    void putAuthenticationTokenInCache(JwtAuthenticationToken token);

    void removeAuthenticationTokenFromCache(String jwt);
}
