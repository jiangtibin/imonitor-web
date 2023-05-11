package com.hengtiansoft.imonitor.web.security.jwt;

import java.util.Optional;

public interface JwtTokenService {

    Optional<? extends JwtToken>findByToken(String token);
}
