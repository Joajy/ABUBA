package com.hexagon.abuba.auth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hexagon.abuba.auth.dto.CustomUserDetails;
import com.hexagon.abuba.auth.dto.request.LoginDTO;
import com.hexagon.abuba.auth.entity.RefreshEntity;
import com.hexagon.abuba.auth.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository) {

        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        CachedBodyHttpServletRequest cachedRequest;
        try {
            cachedRequest = new CachedBodyHttpServletRequest(request);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // JSON 데이터를 파싱
        ObjectMapper objectMapper = new ObjectMapper();
        LoginDTO loginDTO = null;
        try {
            loginDTO = objectMapper.readValue(cachedRequest.getInputStream(), LoginDTO.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        log.info("Parsed LoginDTO: {}", loginDTO);


        String username = loginDTO.email();
        String password = loginDTO.password();

        log.info("username={}", username);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws ServletException, IOException {
        //유저 정보
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 1000L * 60 * 10);
        String refresh = jwtUtil.createJwt("refresh", username, role, 1000L * 60 * 60 * 24);

        //Refresh 토큰 저장
        addRefreshEntity(username, refresh, 1000L * 60 * 60 * 24);

        //응답 설정
        response.setHeader("Authorization", access); //access Token은 헤더에 저장
        response.addCookie(createCookie("refresh", refresh)); //refresh Token은 Cookie에 저장
        response.setStatus(HttpStatus.OK.value());

        //client에서 Authorization 헤더를 사용할 수 있도록 설정
        response.setHeader("Access-Control-Expose-Headers", "Authorization");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        request.setAttribute("user", customUserDetails.getUser());

        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {

        response.setStatus(401);
    }

    //쿠키생성 메서드
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //client에서 js를 사용해서 쿠키에 접근할 수 없도록 막아주는 설정
        cookie.setHttpOnly(true);
        return cookie;
    }

    //refresh토큰을 db에 저장한다.//TODO 향후, redis로 변경해야함
    private void addRefreshEntity(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);
        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());
        refreshRepository.save(refreshEntity);
    }
}
