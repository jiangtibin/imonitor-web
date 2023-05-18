package com.hengtiansoft.imonitor.web.security.validator;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permissions;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({METHOD, FIELD, ANNOTATION_TYPE, CONSTRUCTOR, PARAMETER, TYPE_USE})
@Retention(RUNTIME)
@Documented
@Constraint(validatedBy = PermissionSubsetValidator.class)
public @interface PermissionSubset {
    Permissions subset();
    String message() default "权限集合中包含不合法权限";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}