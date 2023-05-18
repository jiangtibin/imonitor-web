package com.hengtiansoft.imonitor.web.management.client;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/backend/v1/client")
@RequiredArgsConstructor
@PreAuthorize("@webAuthorizer.isWebUser(#root)")
public class ClientController {

    private final ClientService clientService;

    @PostMapping("/registryClient")
    @PreAuthorize("@webAuthorizer.canRegistryClient(#root)")
    public ResponseEntity<ClientVO> registryClient(@Valid @RequestBody ClientDTO clientDTO) {
        return ResponseEntity.ok(clientService.registryClient(clientDTO));
    }
}
