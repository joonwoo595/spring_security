package semiprojectv2m.spring_security.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import semiprojectv2m.spring_security.jwt.JwtTokenProvider;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RequiredArgsConstructor
@Controller
@RequestMapping("/member")
public class UserController {

    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    @GetMapping("/login")
    public String login() {
        return "views/login";
    }

    @PostMapping("/login")
    public String loginok(@RequestParam String userid, @RequestParam String passwd, HttpServletResponse res) {

        log.info(">>/member/login 호출!");

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userid, passwd)
        );


        final String jwt = jwtTokenProvider.generateToken(userid);

// JWT 토큰을 쿠키에 저장
        Cookie cookie = new Cookie("jwt", jwt);
        cookie.setHttpOnly(true);   // 토큰은 header를 통해서만 서버로 전송가능
        cookie.setMaxAge(60 * 30); // 30분
        cookie.setPath("/");
        res.addCookie(cookie);


        return "redirect:/member/myinfo";

    }


    @GetMapping("/myinfo")
    public String myinfo(Authentication authentication, Model model) {
        String returnUrl = "redirect:/member/login";

        // 로그인 인증이 성공했다면
        if(authentication != null && authentication.isAuthenticated()) {
            // 인증 완료된 사용자 정보를 가져옴
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            model.addAttribute("user", userDetails);
            returnUrl = "/views/myinfo";

        }
//        return returnUrl;
        return "views/myinfo";
    }
}
