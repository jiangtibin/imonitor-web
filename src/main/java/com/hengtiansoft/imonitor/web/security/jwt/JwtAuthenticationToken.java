package com.hengtiansoft.imonitor.web.security.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;

    private final Object credentials;

    private final UserDetails userDetails;

    private final int keyHash;

    private final JwtToken token;

    public JwtAuthenticationToken(
            Object principal,
            Object credentials,
            Collection<? extends GrantedAuthority> authorities,
            UserDetails userDetails,
            String key,
            JwtToken token
    ) {
        this(principal, credentials, authorities, userDetails, extractKeyHash(key), token);
    }

    private JwtAuthenticationToken(
            Object principal,
            Object credentials,
            Collection<? extends GrantedAuthority> authorities,
            UserDetails userDetails,
            int keyHash,
            JwtToken token
    ) {
        super(authorities);
        this.credentials = credentials;
        this.principal = principal;
        this.userDetails = userDetails;
        this.keyHash = keyHash;
        this.token = token;
        setAuthenticated(true);
    }

    private static Integer extractKeyHash(String key) {
        Assert.hasLength(key, "key cannot be null or empty");
        return key.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!super.equals(obj)) {
            return false;
        }
        if (obj instanceof JwtAuthenticationToken test) {
            if (!this.token.equals(test.getToken())) {
                return false;
            }
            return this.getKeyHash() == test.getKeyHash();
        }
        return false;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + this.credentials.hashCode();
        result = 31 * result + this.principal.hashCode();
        result = 31 * result + this.userDetails.hashCode();
        result = 31 * result + this.keyHash;
        result = 31 * result + ObjectUtils.nullSafeHashCode(this.token);
        return result;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public int getKeyHash() {return this.keyHash;}

    public JwtToken getToken() {return this.token;}

    public UserDetails getUserDetails() {return this.userDetails;}

    @Override
    public String toString() {
        return (super.toString() +
                " Token: " + this.token);
    }

}
