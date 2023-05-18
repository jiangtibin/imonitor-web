package com.hengtiansoft.imonitor.web.security.entity.client;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record AuthClient(Client client) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Stream.concat(client.getPermissions()
                        .stream()
                        .map(Permission::getPermission)
                        .map(String::toUpperCase)
                        .map(SimpleGrantedAuthority::new), Stream.of(new SimpleGrantedAuthority("ROLE_" + client.getRole())))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return client().getClientId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !client.isLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return client.isEnabled();
    }
}
