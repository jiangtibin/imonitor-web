package com.hengtiansoft.imonitor.web.security.auth;

import com.hengtiansoft.imonitor.web.security.audit.HttpRequestLogHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.web.servlet.function.RequestPredicates.accept;
import static org.springframework.web.servlet.function.RequestPredicates.path;
import static org.springframework.web.servlet.function.RouterFunctions.route;

@Configuration
public class AuthenticationRouterConfig {

    @Bean("authRouter")
    RouterFunction<ServerResponse> authRouter(AuthenticationRequestHandler authRequestHandler) {
        return route()
                .before(HttpRequestLogHandler::preRequestLog)
                .nest(path("/backend/v1/auth"), builder -> builder
                        .POST("/authenticate", accept(APPLICATION_JSON), authRequestHandler::authenticate)
                        .POST("/refreshToken", authRequestHandler::refreshToken)
                )
                .after(HttpRequestLogHandler::postRequestLog)
                .onError(Exception.class, HttpRequestLogHandler::globalErrorLog)
                .build();
    }

}
