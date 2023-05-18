package com.hengtiansoft.imonitor.web.management.user;

import com.hengtiansoft.imonitor.web.security.entity.user.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("/backend/v1/user")
@RequiredArgsConstructor
@PreAuthorize("@webAuthorizer.isWebUser(#root)")
public class UserController {

    private final UserService userService;

    @PostMapping("/registryUser")
    @PreAuthorize("@webAuthorizer.canRegistryUser(#root)")
    public ResponseEntity<User> registryUser(@Valid @RequestBody UserDTO userDTO) {
        return ok().body(userService.registryUser(userDTO));
    }
}
