package semiprojectv2m.spring_security.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor

public class JwtAuthenticationFilter extends OncePerRequestFilter {


    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService;


    // 클라이언트로부터 HTTP요청이 들어오면, 필터 체인에 등록된
    // JwtAuthenticationFilter의 doFilterInternal메서드가 호출
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain fc)
            throws ServletException, IOException {

        log.info(">> JWT Authentication Filter 호출!!");

        String jwt = null;
        String username = null;

        // 헤더 체크
        final String authHeader = req.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
        }

        // 쿠키 체크
        if (jwt == null) {
            Cookie[] cookies = req.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("jwt".equals(cookie.getName())) {
                        jwt = cookie.getValue();
                        break;
                    }
                }
            }
        }

        log.info(">> get username in jwt : {}", jwt);

        if (jwt != null) {
            try {
                username = jwtTokenProvider.extractUsername(jwt);
                log.info(">> get username : {}", username);
            } catch (Exception e) {
                log.error(">> JWT 파싱 실패: {}", e.getMessage());
            }
        }

        // 핵심 인증 처리 로직
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 유효한 토큰인지 검증 (선택)
            if (jwtTokenProvider.validateToken(jwt, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                log.info(">> SecurityContextHolder에 인증 객체 등록 완료!");
            }
        }

        fc.doFilter(req, res); // 필터 계속 진행
    }

}