package com.hexagon.abuba.infra.redis;

import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    public RefreshTokenService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Refresh Token 저장
    public void saveRefreshToken(String username, String refreshToken, Long refreshTokenExpiration) {
        redisTemplate.opsForValue().set(getRedisKey(username), refreshToken, refreshTokenExpiration, TimeUnit.MILLISECONDS);
    }

    // Refresh Token 조회
    public String getRefreshToken(String username) {
        return redisTemplate.opsForValue().get(getRedisKey(username));
    }

    // Refresh Token 삭제
    public void deleteRefreshToken(String username) {
        redisTemplate.delete(getRedisKey(username));
    }

    // Redis Key 생성
    private String getRedisKey(String username) {
        return "refreshToken:" + username;
    }
}