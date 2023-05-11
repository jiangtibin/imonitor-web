package com.hengtiansoft.imonitor.web.security.audit;

import com.hengtiansoft.imonitor.web.security.entity.CachedHttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.springframework.web.servlet.function.ServerResponse.badRequest;

@Slf4j
public class HttpRequestLogHandler {

    public static ServerResponse globalErrorLog(Throwable e, ServerRequest req) {
        log.info(String.format("Error on processing request %s, Cause: %s", req.uri(), e.getMessage()));
        return badRequest().body(e.getMessage());
    }

    public static ServerRequest preRequestLog(ServerRequest req) {
        ServerRequest cachedRequest = null;
        try {
            CachedHttpServletRequest cachedHttpRequest = new CachedHttpServletRequest(req.servletRequest());
            cachedRequest = ServerRequest.create(cachedHttpRequest, req.messageConverters());
            var params = IOUtils.toString(cachedHttpRequest.getInputStream(), StandardCharsets.UTF_8);
            log.info(String.format("Started processing request %s, requested by user %s, with parameters: \n%s",
                    req.uri().getPath(),
                    SecurityContextHolder.getContext().getAuthentication().getName(),
                    params));

            cachedRequest.servletRequest().setAttribute("startAt", System.currentTimeMillis());

            return cachedRequest;
        } catch (IOException e) {
            log.error("Error on logging inComing request: " + req.uri());
        }

        return cachedRequest == null ? req : cachedRequest;
    }

    public static ServerResponse postRequestLog(ServerRequest req, ServerResponse res) {
        var endTime = System.currentTimeMillis();
        var startTime = Long.parseLong(String.valueOf(req.servletRequest().getAttribute("startAt")));
        var duration = endTime - startTime;

        if (res.statusCode() == HttpStatus.OK) {
            log.info(String.format("Finished processing request %s, duration: %sms", req.uri().getPath(), duration));
        } else {
            log.info(String.format("Finished processing request %s with error", req.uri()));
        }

        return res;
    }
}
