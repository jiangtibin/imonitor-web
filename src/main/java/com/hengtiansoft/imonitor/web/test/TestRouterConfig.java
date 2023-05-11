package com.hengtiansoft.imonitor.web.test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.web.servlet.function.RequestPredicates.path;
import static org.springframework.web.servlet.function.RouterFunctions.route;

@Configuration
public class TestRouterConfig {

    @Bean("testRouter")
    RouterFunction<ServerResponse> testRouter() {
        return route()
                .nest(path("/backend/v1/test"), builder -> builder
                        .GET("/testAny", request -> ServerResponse.ok().body("test for any"))
                        .GET("/testAdmin", request -> ServerResponse.ok().body("test for admin"))
                        .GET("/testWebUser", request -> ServerResponse.ok().body("test for web user"))
                        .GET("/testApiUser", request -> ServerResponse.ok().body("test for api user"))
                )
                .build();
    }
}
