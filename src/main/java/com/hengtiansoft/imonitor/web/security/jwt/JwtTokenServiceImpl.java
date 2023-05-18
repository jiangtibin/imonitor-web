package com.hengtiansoft.imonitor.web.security.jwt;

import com.hengtiansoft.imonitor.web.security.entity.token.TokenRepository;
import lombok.RequiredArgsConstructor;

import java.util.Optional;

@RequiredArgsConstructor
public class JwtTokenServiceImpl implements JwtTokenService {

    private final TokenRepository tokenRepository;

    @Override
    public Optional<? extends JwtToken> findByToken(String token) {
        return tokenRepository.findByToken(token);
    }
}
