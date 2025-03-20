package semiprojectv2m.spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.extras.springsecurity5.dialect.SpringSecurityDialect;

import javax.servlet.http.HttpServletResponse;
import java.security.Security;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()   // CSRF 필터 끔
                .authorizeRequests()    // URL 기반 인가 설정
                .antMatchers("/user/**").hasRole("USER")    // USER 궝한 사용자만 접근 가능
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/logout").authenticated()    // 인증 받은 사용자만 접근 가능
                .antMatchers("/**").permitAll()    // 인증/인가 여부와 상관없이 접근 가능
                .and()
                .logout()   // 로그아웃 설정
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessHandler((req,res,auth) -> {
                    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 로그아웃을 위해 401 응답
                })
                .invalidateHttpSession(true)    //세션 무효화
                .deleteCookies("JSESSIONID")    // JSESSIONID 쿠키 삭제
                .permitAll()
                .and()
                .httpBasic();   // HTTP Basic 인증 사용

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}
