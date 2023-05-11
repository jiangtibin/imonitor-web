package com.hengtiansoft.imonitor.web.security.auth;

import com.hengtiansoft.imonitor.web.security.entity.role.Role;
import com.hengtiansoft.imonitor.web.security.entity.token.Token;
import com.hengtiansoft.imonitor.web.security.entity.token.TokenRepository;
import com.hengtiansoft.imonitor.web.security.entity.token.TokenType;
import com.hengtiansoft.imonitor.web.security.entity.user.AuthUser;
import com.hengtiansoft.imonitor.web.security.entity.user.CredentialStrategy;
import com.hengtiansoft.imonitor.web.security.entity.user.User;
import com.hengtiansoft.imonitor.web.security.entity.user.UserRepository;
import com.hengtiansoft.imonitor.web.security.jwt.JwtProvider;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;

@Service
@Validated
@Transactional
@RequiredArgsConstructor
public class AuthenticationService{

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationResponse registry(@Valid RegistrationRequest request) {
        var user = User
                .builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.valueOf(request.role()))
                .permissions(request.permissions())
                .locked(false)
                .enabled(true)
                .credentialStrategy(CredentialStrategy.NEVER)
                .build();

        var authUser = new AuthUser(user);
        var accessToken = jwtProvider.generateAccessToken(authUser);
        var refreshToken = jwtProvider.generateRefreshToken(authUser);
        var savedUser = userRepository.save(authUser.user());
        saveUserToken(savedUser, accessToken, TokenType.ACCESS_TOKEN);
        saveUserToken(savedUser, refreshToken, TokenType.REFRESH_TOKEN);
        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public AuthenticationResponse authenticate(@Valid AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        var authUser = userRepository
                .findByEmail(request.username())
                .map(AuthUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("用户名或密码错误"));

        var accessToken = jwtProvider.generateAccessToken(authUser);
        revokeAllTokens(authUser.user(), TokenType.ACCESS_TOKEN);
        saveUserToken(authUser.user(), accessToken, TokenType.ACCESS_TOKEN);
        var refreshToken = tokenRepository
                .findAllValidTokenByUser(authUser.user().getId(), TokenType.REFRESH_TOKEN)
                .stream()
                .filter(token -> !token.isRevoked() && !token.isExpired())
                .map(Token::getToken)
                .findFirst()
                .orElseGet(() -> {
                   revokeAllTokens(authUser.user(), TokenType.REFRESH_TOKEN);
                   var newRefreshToken = jwtProvider.generateRefreshToken(authUser);
                   saveUserToken(authUser.user(), newRefreshToken, TokenType.REFRESH_TOKEN);
                   return newRefreshToken;
                });

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    public AuthenticationResponse refreshToken(String refreshToken) {
        var token = tokenRepository.findByToken(refreshToken).orElseThrow(() -> new JwtException("Invalid Token"));
        if (token.getTokenType() != TokenType.REFRESH_TOKEN) {
            throw new UnsupportedJwtException("Unsupported token provided, refresh token expected.");
        }

        var userEmail = jwtProvider.extractUsername(token.getToken());
        if (userEmail == null) {
            throw new JwtException("Invalid Token");
        }
        var user = userRepository.findByEmail(userEmail).map(AuthUser::new).orElseThrow(() -> new UsernameNotFoundException("用户不存在"));
        if (!jwtProvider.isTokenExpired(token.getToken())) {
            var accessToken = jwtProvider.generateAccessToken(user);
            revokeAllTokens(user.user(), TokenType.ACCESS_TOKEN);
            saveUserToken(user.user(), accessToken, TokenType.ACCESS_TOKEN);
            return new AuthenticationResponse(accessToken, token.getToken());
        } else {
            revokeAllTokens(user.user(), TokenType.REFRESH_TOKEN);
            throw new JwtException("Token Expired.");
        }
    }

    private void saveUserToken(User user, String jwtToken, TokenType tokenType) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(tokenType)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllTokens(User user, TokenType tokenType) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId(), tokenType);
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

}
