package com.hengtiansoft.imonitor.web.security.entity.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.hengtiansoft.imonitor.web.security.audit.AuditEntity;
import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static com.fasterxml.jackson.annotation.JsonProperty.Access.WRITE_ONLY;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "im_user")
public class User extends AuditEntity {

    @Id
    @GeneratedValue
    private Integer id;

    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    @JsonProperty(access = WRITE_ONLY)
    private String password;

    private boolean locked;

    private boolean enabled;

    @Enumerated(EnumType.STRING)
    private CredentialStrategy credentialStrategy = CredentialStrategy.NEVER;

    private LocalDateTime expiredDate;

    @Enumerated(EnumType.STRING)
    private Role role;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "im_user_permissions",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id", referencedColumnName = "id"))
    private List<Permission> permissions = new ArrayList<>();
}
