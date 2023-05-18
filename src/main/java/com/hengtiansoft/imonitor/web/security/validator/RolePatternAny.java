package com.hengtiansoft.imonitor.web.security.validator;

import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Arrays;
import java.util.List;

public class RolePatternAny implements ConstraintValidator<RoleAny, String> {

    private List<Role> roles;

    @Override
    public void initialize(RoleAny constraintAnnotation) {
        this.roles = Arrays.stream(constraintAnnotation.anyOf()).toList();
    }

    @Override
    public boolean isValid(String roleStr, ConstraintValidatorContext constraintValidatorContext) {
        try {
            Role role = Role.valueOf(roleStr);
            return roles.contains(role);
        } catch (Exception ex) {
            return false;
        }
    }
}
