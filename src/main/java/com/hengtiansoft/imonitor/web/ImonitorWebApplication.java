package com.hengtiansoft.imonitor.web;

import com.hengtiansoft.imonitor.web.security.auth.AuthenticationService;
import com.hengtiansoft.imonitor.web.security.auth.RegistrationRequest;
import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import com.hengtiansoft.imonitor.web.security.entity.permission.Permissions;
import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.stream.Collectors;

@SpringBootApplication
public class ImonitorWebApplication {
    public static void main(String[] args) {
        SpringApplication.run(ImonitorWebApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(
            AuthenticationService service
    ) {
        return args -> {
            var permissions = Permissions.ALL_PERMISSIONS
                    .getPermissions()
                    .stream()
                    .map(Permission::name)
                    .collect(Collectors.toSet());

            var admin = RegistrationRequest.builder()
                    .username("admin")
                    .email("admin@hengtiansoft.com")
                    .password("password123")
                    .role(Role.ADMIN.name())
                    .permissions(permissions)
                    .build();
            System.out.println("Admin accessToken: " + service.register(admin).accessToken());
        };
    }
}
