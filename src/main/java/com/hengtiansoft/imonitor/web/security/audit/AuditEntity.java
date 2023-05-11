package com.hengtiansoft.imonitor.web.security.audit;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@MappedSuperclass
@EntityListeners(AuditTrailListener.class)
public class AuditEntity {
    @Column(name = "CREATE_USER")
    private String createUser;

    @Column(name = "CREATE_AT")
    private LocalDateTime createAt;

    @Column(name = "UPDATE_USER")
    private String updateUser;

    @Column(name = "UPDATE_AT")
    private LocalDateTime updateAt;
}
