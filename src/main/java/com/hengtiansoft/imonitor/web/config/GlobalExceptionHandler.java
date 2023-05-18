package com.hengtiansoft.imonitor.web.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import static java.util.stream.Collectors.toMap;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public void accessDeniedExceptionHandle(HttpServletResponse response) throws IOException {
        response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseBody
    public ResponseEntity<Map<String, String>> argumentsBindingExceptionHandle(
            MethodArgumentNotValidException ex,
            HttpServletRequest req
    ) {
        var message = ex
                .getFieldErrors()
                .stream()
                .collect(toMap(FieldError::getField,
                        fieldError -> Optional.ofNullable(fieldError.getDefaultMessage()).orElse(""),
                        (err1, err2) -> err1 + "," + err2));
        log.info(String.format("Error on processing request %s, Cause: %s", req.getRequestURI(), ex.getMessage()), ex);
        return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON).body(message);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public void messageReadExceptionHandle(HttpMessageNotReadableException ex,
                                           HttpServletRequest req,
                                           HttpServletResponse response) throws IOException {
        log.info(String.format("Error on processing request %s, Cause: %s", req.getRequestURI(), ex.getMessage()), ex);
        response.sendError(HttpStatus.BAD_REQUEST.value(), "请求参数错误");
    }

    @ExceptionHandler(Exception.class)
    public void GlobalExceptionHandle(Exception ex,
                                      HttpServletRequest req,
                                      HttpServletResponse response) throws IOException {
        log.info(String.format("Error on processing request %s, Cause: %s", req.getRequestURI(), ex.getMessage()), ex);
        response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), "系统未知异常");
    }
}
