package com.hengtiansoft.imonitor.web.security.audit;

import jakarta.persistence.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.Objects;

@Slf4j
public class AuditTrailListener {

    @PostPersist
    @PostUpdate
    @PostRemove
    private void logAfterAnyUpdate(Object obj) {
        log.info(String.format("[Audit] entity %s was updated by user %s",
                obj.getClass().getSimpleName(),
                SecurityContextHolder.getContext().getAuthentication().getName()));
    }

    @PrePersist
    private void addCreationAudit(Object obj) {
        try {
            Class<?> superclass = obj.getClass().getSuperclass();
            setCreationInfos(obj, Objects.requireNonNullElseGet(superclass, obj::getClass));
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            log.error("Error on adding creation audit data");
        }
    }

    @PreUpdate
    private void addModificationAudit(Object obj) {
        try {
            Class<?> superclass = obj.getClass().getSuperclass();
            setModificationInfos(obj, Objects.requireNonNullElseGet(superclass, obj::getClass));
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            log.error("Error on adding modification audit data");
        }
    }

    private void setCreationInfos(Object obj, Class<?> clazz)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method setCreateUser = clazz.getDeclaredMethod("setCreateUser", String.class);
        Method setCreateAt = clazz.getDeclaredMethod("setCreateAt", LocalDateTime.class);
        setCreateUser.invoke(obj, SecurityContextHolder.getContext().getAuthentication().getName());
        setCreateAt.invoke(obj, LocalDateTime.now());
    }

    private void setModificationInfos(Object obj, Class<?> clazz)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Method setCreateUser = clazz.getDeclaredMethod("setUpdateUser", String.class);
        Method setCreateAt = clazz.getDeclaredMethod("setUpdateAt", LocalDateTime.class);
        setCreateUser.invoke(obj, SecurityContextHolder.getContext().getAuthentication().getName());
        setCreateAt.invoke(obj, LocalDateTime.now());
    }
}
