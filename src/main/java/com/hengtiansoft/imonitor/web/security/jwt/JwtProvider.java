package com.hengtiansoft.imonitor.web.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.Nonnull;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Key;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class JwtProvider {

    private static final int DEFAULT_OFFSET = 15 * 60 * 1000;

    private final JwtProperties tokenProperties;

    public JwtProvider(JwtProperties tokenProperties) {
        this.tokenProperties = tokenProperties;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateAccessToken(new HashMap<>(), userDetails);
    }

    public String generateAccessToken(
            @Nonnull Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, parseTimeOffset(tokenProperties.getAccessTokenExpiration()));
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return generateRefreshToken(new HashMap<>(), userDetails);
    }

    public String generateRefreshToken(
            @Nonnull Map<String, Object> extraClaims,
            UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, parseTimeOffset(tokenProperties.getRefreshTokenExpiration()));
    }

    private String buildToken(
            @Nonnull Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(tokenProperties.getSecretKey());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private int parseTimeOffset(String expiredTime) {
        if (Strings.isBlank(expiredTime)) {
            return DEFAULT_OFFSET;
        }

        if (expiredTime.contains("*")) {
            return Arrays
                    .stream(expiredTime.split("\\*"))
                    .mapToInt(Integer::parseInt)
                    .reduce(1, Math::multiplyExact);
        } else {
            return Integer.parseInt(expiredTime);
        }
    }
}
