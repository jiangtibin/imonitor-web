package com.hengtiansoft.imonitor.web.management.client;

import com.hengtiansoft.imonitor.web.security.entity.client.AuthClient;
import com.hengtiansoft.imonitor.web.security.entity.client.Client;
import com.hengtiansoft.imonitor.web.security.entity.client.ClientRepository;
import com.hengtiansoft.imonitor.web.security.entity.permission.Permission;
import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import com.hengtiansoft.imonitor.web.security.entity.token.Token;
import com.hengtiansoft.imonitor.web.security.entity.token.TokenRepository;
import com.hengtiansoft.imonitor.web.security.entity.token.TokenType;
import com.hengtiansoft.imonitor.web.security.jwt.JwtProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@Transactional
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService{

    private final ClientRepository clientRepository;

    private final TokenRepository tokenRepository;

    private final JwtProvider jwtProvider;

    @Override
    public ClientVO registryClient(ClientDTO clientDTO) {
        clientRepository
                .findByClientId(clientDTO.clientId())
                .ifPresent(client -> {
                    throw new RuntimeException("添加失败，Client ID已存在");
                });

        var permissions = clientDTO.permissions().stream().map(Permission::valueOf).collect(Collectors.toSet());
        var client = Client
                .builder()
                .clientId(clientDTO.clientId())
                .clientName(clientDTO.clientName())
                .description(clientDTO.description())
                .role(Role.API_USER)
                .permissions(permissions)
                .locked(false)
                .enabled(true)
                .build();
        Client savedClient = clientRepository.save(client);
        var apiToken = jwtProvider.generateApiToken(new AuthClient(savedClient));
        var token = Token
                .builder()
                .client(savedClient)
                .token(apiToken)
                .tokenType(TokenType.API_TOKEN)
                .expired(false)
                .revoked(false)
                .build();
        var savedToken = tokenRepository.save(token);
        return new ClientVO(savedClient, savedToken);
    }
}
