package com.hengtiansoft.imonitor.web.security.entity.token;

import com.hengtiansoft.imonitor.web.security.jwt.JwtToken;
import com.hengtiansoft.imonitor.web.security.jwt.JwtTokenService;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

@RequiredArgsConstructor
public class TokenService implements JwtTokenService {

    private final TokenRepository tokenRepository;

    @Override
    public Optional<? extends JwtToken> findByToken(String token) {
        return tokenRepository.findByToken(token);
    }
}
