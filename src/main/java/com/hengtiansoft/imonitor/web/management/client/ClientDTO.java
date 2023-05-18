package com.hengtiansoft.imonitor.web.management.client;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permissions;
import com.hengtiansoft.imonitor.web.security.validator.PermissionSubset;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record ClientDTO(
        @NotEmpty(message = "Client ID 不能为空")
        String clientId,

        String clientName,

        String description,

        @NotNull
        @PermissionSubset(subset = Permissions.API_PERMISSIONS)
        Set<String> permissions
) {
}
