package com.securiy.realsecurity.config;

import com.securiy.realsecurity.common.AjaxLoginAuthenticationEntryPoint;
import com.securiy.realsecurity.filter.AjaxLoginProcessingFilter;
import com.securiy.realsecurity.handler.AjaxAccessDeniedHandler;
import com.securiy.realsecurity.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Order(0)
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    /*
     *  SecurityConfig.java에 AuthenticationSuccessHandler 타입으로 폼객체용 핸들러를 빈으로 주입하고 있기 때문에
     *  ajax용 핸들러 빈이 없으면 Form방식용 success, failure handler가 적용된다. 따라서 200 OK값이 나오게 됨. 조심하자.
     */
    private final AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler;
    private final AuthenticationFailureHandler ajaxAuthenticationFailureHandler;
    private final AjaxAccessDeniedHandler ajaxAccessDeniedHandler;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .anyRequest().authenticated()
        ;

        http
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .accessDeniedHandler(ajaxAccessDeniedHandler); // 인증을 했지만 권한이 없는 경우

        /**
         * .addFilterBefore() : 추가하고자 하는 필터가 기존 필터보다 앞에 위치
         * .addFilter() : 필터들 중 가장 뒤에 위치
         * .addFilterAfter() : 추가하고자 하는 필터가 기존 필터 뒤쪽
         * .addFilterAt() : 추가하고자 하는 필터가 기존 필터 위치 대체할 때 이용
         */
//        http
//                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        http.csrf().disable();

        customConfigurerAjax(http);


        /* 위에서 커스텀했다.*/
//        http
//                .exceptionHandling()
                // 스프링 시큐리티는 form형식의 인증 경로만 제공하기 때문에 REST형식인 경우 예외 발생 시 로그인 페이지로 돌아가게 지정한 것
//                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//        ;
    }

    private void customConfigurerAjax(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler)
                .failureHandlerAjax(ajaxAuthenticationFailureHandler)
                .setAuthenticationManager(authenticationManagerBean())
                .loginProcessingUrl("/api/login")
        ;
    }

    /* customConfigurerAjax 활성화 시 주석처리 */
//    @Bean
//    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
//        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
//        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
//        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler);
//        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler);
//        return ajaxLoginProcessingFilter;
//    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider(customUserDetailsService,passwordEncoder);
    }

}
