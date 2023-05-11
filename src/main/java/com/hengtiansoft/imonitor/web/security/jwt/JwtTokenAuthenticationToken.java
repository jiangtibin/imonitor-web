package com.hengtiansoft.imonitor.web.security.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.io.Serial;
import java.util.ArrayList;

public class JwtTokenAuthenticationToken extends AbstractAuthenticationToken  {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String username;
    private final String token;

    public JwtTokenAuthenticationToken(final String username, final String token) {
        super(new ArrayList<>());
        this.username = username;
        this.token = token;
    }

    @Override
    public Object getCredentials() {
        return this.token;
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }

}
