package com.hengtiansoft.imonitor.web.security.entity.permission;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "im_permission")
public class Permission {

    @Id
    @GeneratedValue
    private Integer id;

    @Column(nullable = false, unique = true)
    private String code;

    private String description;

    private boolean enabled;

    @Enumerated(EnumType.STRING)
    private PermissionType permissionType;

}
