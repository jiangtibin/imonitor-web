package com.hengtiansoft.imonitor.web.security.entity.user;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record AuthUser(User user) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Stream.concat(user.getPermissions()
                .stream()
                .map(Permission::getPermission)
                .map(String::toUpperCase)
                .map(SimpleGrantedAuthority::new), Stream.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user.getCredentialStrategy().equals(CredentialStrategy.NEVER) ||
                !user.getCredentialStrategy().equals(CredentialStrategy.IMMEDIATE)
                        && user.getExpiredDate().isAfter(LocalDateTime.now());
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}
