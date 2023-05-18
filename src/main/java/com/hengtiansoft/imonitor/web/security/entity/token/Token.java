package com.hengtiansoft.imonitor.web.security.entity.token;

import com.hengtiansoft.imonitor.web.security.audit.AuditEntity;
import com.hengtiansoft.imonitor.web.security.entity.client.Client;
import com.hengtiansoft.imonitor.web.security.entity.user.User;
import com.hengtiansoft.imonitor.web.security.jwt.JwtToken;
import jakarta.persistence.*;
import lombok.*;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "im_token")
public class Token extends AuditEntity implements JwtToken {

    @Id
    @GeneratedValue
    private Long id;

    @Column(length = 512, nullable = false)
    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    private boolean revoked;

    private boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "clietn_id")
    private Client client;

    @Override
    public String getTokenString() {
        return this.token;
    }
}
