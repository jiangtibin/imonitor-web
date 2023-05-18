package com.hengtiansoft.imonitor.web.security.jwt;

import com.hengtiansoft.imonitor.web.security.entity.token.TokenType;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

import javax.annotation.Nonnull;

public class JwtAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {

    private AuthenticationUserDetailsService<JwtTokenAuthenticationToken> authenticationUserDetailsService;

    private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    private JwtTokenCache jwtTokenCache = new NullJwtTokenCache();

    private String key;

    private JwtProvider jwtProvider;

    private JwtTokenService jwtService;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(this.authenticationUserDetailsService, "An authenticationUserDetailsService must be set");
        Assert.notNull(this.jwtProvider, "A jwt token provider must be set");
        Assert.notNull(this.jwtService, "A jwt token repository must be set");
        Assert.notNull(this.jwtTokenCache, "A jwt token cache must be set");
        Assert.hasText(this.key,
                "A Key is required so JwtAuthenticationProvider can identify tokens it previously authenticated");
        Assert.notNull(this.messages, "A message source must be set");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication instanceof JwtAuthenticationToken) {
            if (this.key.hashCode() != ((JwtAuthenticationToken) authentication).getKeyHash()) {
                throw new BadCredentialsException(this.messages.getMessage("JwtAuthenticationProvider.incorrectKey",
                        "The presented JwtAuthenticationToken does not contain the expected key"));
            }
            return authentication;
        }

        if ((authentication.getCredentials() == null) || "".equals(authentication.getCredentials())) {
            throw new BadCredentialsException(this.messages.getMessage("JwtAuthenticationProvider.noJwtToken",
                    "Failed to provide a JWT token to validate"));
        }

        JwtAuthenticationToken result = this.jwtTokenCache.getByJwtToken(authentication.getCredentials().toString());

        if (result == null) {
            result = this.authenticationNow(authentication);
            result.setDetails(authentication.getDetails());
            this.jwtTokenCache.putAuthenticationTokenInCache(result);
        }

        return result;
    }

    private JwtAuthenticationToken authenticationNow(final Authentication authentication) throws AuthenticationException {
        try {
            final JwtTokenAuthenticationToken jwtTokenAuthenticationToken = (JwtTokenAuthenticationToken) authentication;
            JwtToken token = this.jwtService
                    .findByToken(jwtTokenAuthenticationToken.getCredentials().toString())
                    .orElseThrow(() -> new JwtException("Token not found"));

            if (jwtTokenAuthenticationToken.getTokenType() != TokenType.ACCESS_TOKEN
                    && jwtTokenAuthenticationToken.getTokenType() != TokenType.API_TOKEN) {
                throw new JwtException("unSupport token type");
            }

            if (jwtProvider.isTokenExpired(token.getTokenString())) {
                throw new JwtException("Token expired");
            }

            if (token.isExpired() || token.isRevoked()) {
                throw new JwtException("Token revoked");
            }

            UserDetails userDetails = this.loadUserByToken(jwtTokenAuthenticationToken);
            this.userDetailsChecker.check(userDetails);
            return new JwtAuthenticationToken(userDetails, authentication.getCredentials(),
                    this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities()), userDetails, this.key, token);
        } catch (JwtException ex) {
            throw new BadCredentialsException(this.messages.getMessage("JwtAuthenticationProvider.invalidToken",
                    "Invalid Token: " + ex.getMessage()));
        }
    }

    protected UserDetails loadUserByToken(JwtTokenAuthenticationToken jwtTokenAuthenticationToken) {
        return this.authenticationUserDetailsService.loadUserDetails(jwtTokenAuthenticationToken);
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setAuthenticationUserDetailsService(
            final AuthenticationUserDetailsService<JwtTokenAuthenticationToken> authenticationUserDetailsService) {
        this.authenticationUserDetailsService = authenticationUserDetailsService;
    }

    public void setJwtProvider(JwtProvider jwtProvider) {this.jwtProvider = jwtProvider;}

    public void setJwtService(JwtTokenService jwtService) {this.jwtService = jwtService;}

    public void setJwtTokenCache(JwtTokenCache jwtTokenCache) {this.jwtTokenCache = jwtTokenCache;}

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication))
                || (JwtTokenAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    public void setMessageSource(@Nonnull final MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }
}
