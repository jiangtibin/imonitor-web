package com.hengtiansoft.imonitor.web.security.entity.permission;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.hengtiansoft.imonitor.web.security.entity.permission.PermissionType.API;
import static com.hengtiansoft.imonitor.web.security.entity.permission.PermissionType.MENU;

public enum Permissions {
    ALL_PERMISSIONS {
        @Override
        public Set<Permission> getPermissions() {
            return new HashSet<>(EnumSet.allOf(Permission.class));
        }
    },
    MENU_PERMISSIONS {
        @Override
        public Set<Permission> getPermissions() {
            return EnumSet.allOf(Permission.class)
                    .stream()
                    .filter(permissions -> permissions.getPermissionType() == MENU)
                    .collect(Collectors.toSet());
        }
    },
    API_PERMISSIONS {
        @Override
        public Set<Permission> getPermissions() {
            return EnumSet.allOf(Permission.class)
                    .stream()
                    .filter(permissions -> permissions.getPermissionType() == API)
                    .collect(Collectors.toSet());
        }
    };

    public Set<Permission> getPermissions() {
        return new HashSet<>();
    }
}
