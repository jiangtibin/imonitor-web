package com.hengtiansoft.imonitor.web.security.jwt;

public class NullJwtTokenCache implements JwtTokenCache {
    @Override
    public JwtAuthenticationToken getByJwtToken(String jwt) {
        return null;
    }

    @Override
    public void putAuthenticationTokenInCache(JwtAuthenticationToken token) {
        // nothing to do
    }

    @Override
    public void removeAuthenticationTokenFromCache(String jwt) {
        // nothing to do
    }
}
