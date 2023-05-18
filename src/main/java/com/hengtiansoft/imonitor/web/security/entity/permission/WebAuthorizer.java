package com.hengtiansoft.imonitor.web.security.entity.permission;

import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.stereotype.Component;

@Component
public class WebAuthorizer {

    public boolean isWebUser(MethodSecurityExpressionOperations root) {
        return root.hasAnyRole(Role.ADMIN.name(), Role.WEB_USER.name());
    }

    public boolean canRegistryUser(MethodSecurityExpressionOperations root) {
        return root.hasAuthority(Permission.USER_ADD.getPermission());
    }

    public boolean canRegistryClient(MethodSecurityExpressionOperations root) {
        return root.hasAuthority(Permission.CLIENT_ADD.getPermission());
    }
}
