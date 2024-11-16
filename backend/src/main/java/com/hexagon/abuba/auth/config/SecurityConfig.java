package com.hexagon.abuba.auth.config;

import com.hexagon.abuba.auth.jwt.CustomLogoutFilter;
import com.hexagon.abuba.auth.jwt.JWTFilter;
import com.hexagon.abuba.auth.jwt.JWTUtil;
import com.hexagon.abuba.auth.jwt.LoginFilter;
import com.hexagon.abuba.auth.repository.RefreshRepository;
import com.hexagon.abuba.auth.service.CustomUserDetailsService;
import com.hexagon.abuba.infra.redis.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    private final CustomUserDetailsService customUserDetailsService;
    private final RefreshTokenService refreshTokenService;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil, RefreshRepository refreshRepository, CustomUserDetailsService customUserDetailsService,
                          RefreshTokenService refreshTokenService) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
        this.customUserDetailsService = customUserDetailsService;
        this.refreshTokenService = refreshTokenService;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        LoginFilter loginFilter = new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshRepository,
                refreshTokenService);
        loginFilter.setFilterProcessesUrl("/api/v1/auth/login");

        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.addAllowedOriginPattern("*");
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);
                        configuration.setExposedHeaders(Collections.singletonList("access"));
                        return configuration;
                    }
                })));

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //Form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/actuator/health","/actuator/metrics/**").permitAll() // 'health' 엔드포인트는 모두에게 허용
                        .requestMatchers("/v3/**", "/swagger-ui/**","/swagger/**","/docs/**").permitAll()// Swagger UI 및 API 문서 접근 허용
                        .requestMatchers("/api/v1/auth/login", "/",
                                "/api/v1/auth/signup", "/api/v1/auth/logout",
                                "/api/v1/auth/verify-email","/api/v1/auth/send-email", "/api/v1/auth/reissue").permitAll()
                        .requestMatchers("/reissue").permitAll()
                        .anyRequest().authenticated());
        http
                .addFilterBefore(new JWTFilter(jwtUtil, customUserDetailsService), LoginFilter.class);
        http
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);
        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository), LogoutFilter.class);
        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
