package com.hengtiansoft.imonitor.web.security.validator;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Set;

public class PermissionSubsetValidator implements ConstraintValidator<PermissionSubset, Set<String>> {

    private Set<Permission> permissionSet;
    @Override
    public void initialize(PermissionSubset constraintAnnotation) {
        this.permissionSet = constraintAnnotation.subset().getPermissions();
    }

    @Override
    public boolean isValid(Set<String> permissions, ConstraintValidatorContext constraintValidatorContext) {
        try {
            return permissions
                    .stream()
                    .map(Permission::valueOf)
                    .allMatch(permissionSet::contains);
        } catch (Exception ex) {
            return false;
        }
    }
}
