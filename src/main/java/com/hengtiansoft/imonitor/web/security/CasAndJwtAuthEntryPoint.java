package com.hengtiansoft.imonitor.web.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apereo.cas.client.authentication.AuthenticationRedirectStrategy;
import org.apereo.cas.client.authentication.DefaultAuthenticationRedirectStrategy;
import org.apereo.cas.client.util.CommonUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class CasAndJwtAuthEntryPoint implements AuthenticationEntryPoint, InitializingBean {

    private ServiceProperties serviceProperties;

    private String loginUrl;

    private boolean encodeServiceUrlWithSessionId = true;

    private Boolean casEnabled = true;

    private Boolean jwtEnabled = true;

    private AuthenticationRedirectStrategy authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy();

    @Override
    public void afterPropertiesSet(){
        Assert.hasLength(this.loginUrl, "loginUrl must be specified");
        Assert.notNull(this.serviceProperties, "serviceProperties must be specified");
        Assert.notNull(this.serviceProperties.getService(), "serviceProperties.getService() cannot be null.");
        Assert.notNull(this.casEnabled, "casEnabled must have a value of true or false");
        Assert.notNull(this.jwtEnabled, "jwtEnabled must have a value of true or false");
    }

    @Override
    public final void commence(final HttpServletRequest request, HttpServletResponse response,
                               AuthenticationException authenticationException) throws IOException {
        final String authHeader = request.getHeader("Authorization");
        if (jwtEnabled && authHeader != null && authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            PrintWriter out = response.getWriter();
            response.setContentType(MediaType.APPLICATION_JSON.toString());
            var res = """
                        {
                            "code:": 1001,
                            "error": %s
                        }
                    """;
            out.write(String.format(res, authenticationException.getMessage()));
            return;
        }


        if (casEnabled) {
            String urlEncodedService = createServiceUrl(request, response);
            String redirectUrl = createRedirectUrl(urlEncodedService);
            this.authenticationRedirectStrategy.redirect(request, response, redirectUrl);
            return;
        }

        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    }

    protected String createServiceUrl(HttpServletRequest request, HttpServletResponse response) {
        return CommonUtils.constructServiceUrl(request, response, this.serviceProperties.getService(), null,
                this.serviceProperties.getArtifactParameter(), this.serviceProperties.getServiceParameter(), this.encodeServiceUrlWithSessionId);
    }

    protected String createRedirectUrl(String serviceUrl) {
        return CommonUtils.constructRedirectUrl(this.loginUrl, this.serviceProperties.getServiceParameter(), serviceUrl,
                this.serviceProperties.isSendRenew(), false);
    }

    public final void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public final void setServiceProperties(ServiceProperties serviceProperties) {
        this.serviceProperties = serviceProperties;
    }

    public final void setEncodeServiceUrlWithSessionId(boolean encodeServiceUrlWithSessionId) {
        this.encodeServiceUrlWithSessionId = encodeServiceUrlWithSessionId;
    }

    public final void setCasEnabled(Boolean casEnabled) {
        this.casEnabled = casEnabled;
    }

    public final void setJwtEnabled(Boolean jwtEnabled) {
        this.jwtEnabled = jwtEnabled;
    }

    public void setAuthenticationRedirectStrategy(AuthenticationRedirectStrategy authenticationRedirectStrategy) {
        Assert.notNull(authenticationRedirectStrategy, "authenticationRedirectStrategy must not be null");
        this.authenticationRedirectStrategy = authenticationRedirectStrategy;
    }
}
