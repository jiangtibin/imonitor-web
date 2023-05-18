package com.hengtiansoft.imonitor.web.security.auth;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permissions;
import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import com.hengtiansoft.imonitor.web.security.validator.PermissionSubset;
import com.hengtiansoft.imonitor.web.security.validator.RoleAny;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;

import java.util.Set;

@Builder
public record RegistrationRequest(

        @NotBlank(message = "用户名不能为空")
        String username,

        @NotBlank(message = "邮箱不能为空")
        @Email(message = "请输入正确的邮箱地址: xxx@hengtiansoft.com|xxx@insigma.com",
                regexp = "^[a-zA-Z0-9_!#$%&’*+/=?`{|}~^.\\-]+@(hengtiansoft.com|insigma.com)$")
        String email,

        @NotBlank(message = "密码不能为空")
        @Size(min = 8, message = "密码长度必须大于8位")
        String password,

        @RoleAny(anyOf = {Role.ADMIN, Role.WEB_USER})
        String role,

        @NotNull
        @PermissionSubset(subset = Permissions.ALL_PERMISSIONS)
        Set<String> permissions
) {
}
