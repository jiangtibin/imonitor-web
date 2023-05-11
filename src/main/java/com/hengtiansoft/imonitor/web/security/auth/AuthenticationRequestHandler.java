package com.hengtiansoft.imonitor.web.security.auth;

import jakarta.servlet.ServletException;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.io.IOException;

import static org.springframework.web.servlet.function.ServerResponse.badRequest;
import static org.springframework.web.servlet.function.ServerResponse.ok;

@Component
public record AuthenticationRequestHandler(AuthenticationService authService) {

    public ServerResponse registry(ServerRequest req) throws ServletException, IOException {
        return ok().body(authService.registry(req.body(RegistrationRequest.class)));
    }
    public ServerResponse authenticate(ServerRequest req) throws ServletException, IOException {
        return ok().body(authService.authenticate(req.body(AuthenticationRequest.class)));
    }

    public ServerResponse refreshToken(ServerRequest req) throws ServletException, IOException {
        final String authorization = req.servletRequest().getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return badRequest().body("请在请求头中设置 Bearer Authorization refreshToken");
        }
        return ok().body(authService.refreshToken(authorization.substring(7)));
    }
}
