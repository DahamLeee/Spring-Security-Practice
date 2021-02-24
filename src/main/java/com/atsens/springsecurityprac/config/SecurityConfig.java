package com.atsens.springsecurityprac.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER");
        auth.inMemoryAuthentication().withUser("manager").password("{noop}1234").roles("MANAGER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http    // 인가 정책
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('MANAGER')")
                .anyRequest().authenticated()
        ;

        http    // 인증 정책
                .formLogin()
//                .loginPage("/loginPage")  // custom login page 로 가라!
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login")
                .successHandler(new AuthenticationSuccessHandler() {
                    /**
                     * 어떠한 사용자가 request 를 보냈을 때 인증 혹은 인가가 필요해서 로그인을 한 후에
                     * request 를 보낸 페이지를 기억했다가 해당 페이지로 이동하게 하는 로직임
                     * 근데 이거를 Config 에다가 모두 때려 박는 것이 아니라 실전에서는 따로 success handler 객체를 커스텀으로 구현함
                     */
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("# Security Config : exception " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()
        .and()
                .rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // Default 는 14일
                .alwaysRemember(false) // 리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService)
        ;
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .deleteCookies("JSESSIONID", "remember-me")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/");
                    }
                })
        ;

        http     // 동시 접속 제어 (세션 중복)
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
        .and()  // 세션 고정 보호
                .sessionFixation()
                .changeSessionId()
        ;

        http
                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {      // 인증 예외
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {        // 인가 예외
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        ;

    }
}
