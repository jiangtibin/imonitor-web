package com.hengtiansoft.imonitor.web.management.user;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permissions;
import com.hengtiansoft.imonitor.web.security.validator.PermissionSubset;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.Set;

public record UserDTO(
        @NotBlank(message = "用户名不能为空")
        String username,

        @NotBlank(message = "邮箱不能为空")
        @Email(message = "请输入正确的邮箱地址: xxx@hengtiansoft.com|xxx@insigma.com",
                regexp = "^[a-zA-Z0-9_!#$%&’*+/=?`{|}~^.\\-]+@(hengtiansoft.com|insigma.com)$")
        String email,

        @NotNull
        @PermissionSubset(subset = Permissions.MENU_PERMISSIONS)
        Set<String> permissions,

        @Pattern(message = "密码过期策略必须符合下列任意一种：NEVER|IMMEDIATE|DATETIME",
                regexp = "^(NEVER|IMMEDIATE|DATETIME)$")
        String credentialStrategy
) {
}
