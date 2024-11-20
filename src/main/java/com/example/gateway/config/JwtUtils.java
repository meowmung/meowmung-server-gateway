package com.example.gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import java.util.Map;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {
    private final SecretKey key; // secret Key

    public JwtUtils(
            @Value("${jwt.secret}") String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public boolean isValidToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(key)
                    .build()// key는 서명 검증에 사용되는 Secret Key입니다
                    .parseClaimsJws(token); // 토큰의 서명을 검증하고 클레임을 파싱합니다
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            throw new SecurityException(e.getMessage());
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException(e.getHeader(), e.getClaims(), e.getMessage());
        } catch (UnsupportedJwtException e) {
            throw new UnsupportedJwtException(e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public Map<String, Object>  parseToken(String token) {
        // JWT 토큰을 파싱하여 Claims를 추출
        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // 예: Claims에서 필요한 사용자 정보를 Map으로 반환
        // "memberId"라는 클레임이 있다고 가정
        return Map.of(
                "email", claims.getSubject(), // 필요에 따라 추가
                "nickname", claims.get("nickname")
                );
    }

}