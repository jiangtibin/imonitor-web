package com.hengtiansoft.imonitor.web.management.user;

import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import com.hengtiansoft.imonitor.web.security.entity.user.CredentialStrategy;
import com.hengtiansoft.imonitor.web.security.entity.user.User;
import com.hengtiansoft.imonitor.web.security.entity.user.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;

    private final Clock clock;

    private final PasswordEncoder passwordEncoder;

    @Override
    public User registryUser(UserDTO userDTO) {
        var permissions = userDTO.permissions().stream().map(Permission::valueOf).collect(Collectors.toSet());
        var credentialStrategy = CredentialStrategy
                .valueOf(Objects.requireNonNullElse(userDTO.credentialStrategy(), CredentialStrategy.DATETIME.name()));
        var datetime = switch (credentialStrategy) {
            case DATETIME -> OffsetDateTime.now(clock).plusMonths(3).toLocalDateTime();
            case IMMEDIATE, NEVER -> null;
        };
        var password = "Ht@" + LocalDateTime.now(clock).getYear();
        System.out.println(password);
        var user = User
                .builder()
                .username(userDTO.username())
                .email(userDTO.email())
                .password(passwordEncoder.encode(password))
                .role(Role.WEB_USER)
                .permissions(permissions)
                .credentialStrategy(credentialStrategy)
                .expiredDate(datetime)
                .locked(false)
                .enabled(true)
                .build();

        return userRepository.save(user);
    }
}
