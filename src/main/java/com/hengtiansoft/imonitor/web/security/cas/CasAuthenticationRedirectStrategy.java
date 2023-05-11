package com.hengtiansoft.imonitor.web.security.cas;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apereo.cas.client.authentication.AuthenticationRedirectStrategy;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.io.PrintWriter;

public class CasAuthenticationRedirectStrategy implements AuthenticationRedirectStrategy {

    @Override
    public void redirect(
            @Nonnull HttpServletRequest httpServletRequest,
            @Nonnull HttpServletResponse httpServletResponse,
            String potentialRedirectUrl) throws IOException {

        httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON.toString());
        PrintWriter out = httpServletResponse.getWriter();
        var res = """
                        {
                            "code:": 1002,
                            "redirectUrl": %s
                        }
                    """;
        out.write(String.format(res, potentialRedirectUrl));
    }
}
