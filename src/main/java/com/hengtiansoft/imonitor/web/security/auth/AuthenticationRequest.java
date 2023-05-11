package com.hengtiansoft.imonitor.web.security.auth;

import jakarta.validation.constraints.NotBlank;

public record AuthenticationRequest(
        @NotBlank(message = "用户名不能为空")
        String username,

        @NotBlank(message = "密码不能为空")
        String password)
{
}
