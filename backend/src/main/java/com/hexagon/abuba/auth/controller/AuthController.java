package com.hexagon.abuba.auth.controller;

import com.hexagon.abuba.auth.dto.request.JoinDTO;
import com.hexagon.abuba.auth.dto.request.LoginDTO;
import com.hexagon.abuba.auth.dto.request.SendEmailDTO;
import com.hexagon.abuba.auth.dto.request.VerifyEmailDTO;
import com.hexagon.abuba.auth.dto.response.LoginResDTO;
import com.hexagon.abuba.auth.entity.RefreshEntity;
import com.hexagon.abuba.auth.jwt.JWTUtil;
import com.hexagon.abuba.auth.repository.RefreshRepository;
import com.hexagon.abuba.auth.service.AuthService;
import com.hexagon.abuba.common.DataResponse;
import com.hexagon.abuba.common.MessageResponse;
import com.hexagon.abuba.infra.redis.RefreshTokenService;
import com.hexagon.abuba.user.Parent;
import io.jsonwebtoken.ExpiredJwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Date;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@CrossOrigin("*")
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public AuthController(AuthService authService, JWTUtil jwtUtil, RefreshRepository refreshRepository,
                          RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
        this.refreshTokenService = refreshTokenService;
    }

    @Operation(summary = "회원가입", description = "신규 유저가 회원가입합니다.")
    @PostMapping("/signup")
    public ResponseEntity<MessageResponse> signup(@RequestBody JoinDTO joinDTO) {
        authService.joinProcess(joinDTO);
        return new ResponseEntity<>(MessageResponse.of(HttpStatus.OK,"회원가입이 완료되었습니다."),HttpStatus.OK);
    }

    @Operation(summary = "로그인", description = "로그인 합니다.")
    @PostMapping("/login")
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Request body for Swagger",
            required = true
    )
    public ResponseEntity<DataResponse<LoginResDTO>> login(LoginDTO loginDTO,  @Parameter(hidden = true)  HttpServletRequest request) {
        Parent user = (Parent)request.getAttribute("user");
        boolean isEmpty = authService.checkOnboarding(user.getId());
        LoginResDTO  response = new LoginResDTO(user.getUsername(),user.getName(), isEmpty);
        return new ResponseEntity<>(DataResponse.of(HttpStatus.OK,"로그인이 완료되었습니다.",response),HttpStatus.OK);
    }

    @SecurityRequirement(name = "bearerAuth")  // 이 API는 토큰이 필요함
    @Operation(summary = "로그아웃", description = "로그아웃")
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(){
        return new ResponseEntity<>(MessageResponse.of(HttpStatus.OK,"로그아웃 되었습니다."),HttpStatus.OK);
    }

    //이메일 인증 관련로직
    // 이메일 입력 후 인증 요청 (회원가입 도중 이메일 확인)
    @Operation(summary = "이메일 인증 번호 요청", description = "사용자가 입력한 이메일로 인증번호를 보냅니다.")
    @PostMapping("/send-email")
    public ResponseEntity<String> sendVerificationEmail(@RequestBody SendEmailDTO request) {
        authService.sendVerificationEmail(request.email());
        return ResponseEntity.ok("이메일로 인증 링크가 발송되었습니다.");
    }

    // 이메일 인증 링크 확인
    @PostMapping("/verify-email")
    public ResponseEntity<String> verifyEmail(@RequestBody VerifyEmailDTO request) {
        String token = request.token();
        boolean isVerified = authService.verifyEmail(token);
        if (isVerified) {
            return ResponseEntity.ok("이메일 인증 성공!");
        } else {
            return ResponseEntity.badRequest().body("잘못된 또는 만료된 인증 토큰입니다.");
        }
    }

    //refresh토큰
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // Refresh Token 쿠키에서 가져오기
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {

            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        //expired check
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            //response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // Redis에서 Refresh Token 조회
        String username = jwtUtil.getUsername(refresh);
        String storedRefreshToken = refreshTokenService.getRefreshToken(username);
        if (storedRefreshToken == null || !storedRefreshToken.equals(refresh)) {
            return new ResponseEntity<>("Invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 새로운 Access Token과 Refresh Token 생성
        String role = jwtUtil.getRole(refresh);
        String newAccess = jwtUtil.createJwt("access", username, role, 1000L * 60 * 10); // 10분
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 1000L * 60 * 60 * 24); // 24시간

        // Redis 갱신
        refreshTokenService.saveRefreshToken(username, newRefresh, 1000L * 60 * 60 * 24);

        // 응답 설정
        response.setHeader("Authorization", newAccess);
        response.addCookie(createCookie("refresh", newRefresh));

        return new ResponseEntity<>(HttpStatus.OK);
    }

    //쿠키생성 메서드
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //client에서 js를 사용해서 쿠키에 접근할 수 없도록 막음.
        cookie.setHttpOnly(true);
        //path 설정
        cookie.setPath("/reissue");
        return cookie;
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

}
