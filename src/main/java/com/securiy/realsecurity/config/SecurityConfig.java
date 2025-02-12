package com.securiy.realsecurity.config;

import com.securiy.realsecurity.filter.AjaxLoginProcessingFilter;
import com.securiy.realsecurity.handler.CustomAccessDeniedHandler;
import com.securiy.realsecurity.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Order(1)
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService customUserDetailsService;
    private final AuthenticationDetailsSource formAuthenticationDetailsSource;
    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final AuthenticationFailureHandler customAuthenticationFailureHandler;

    /**
     *  AuthenticationManager는 스프링 시큐리티에서는 초기화 시 생성하게 됨 -> 빈이 아니라 일반 객체로!
     *  스프링 시큐리티는 HttpSecurity에 있는 SharedObject를 가지고 여기에 객체들을 넣어놓고 참조하는 식으로 운용함.(빈이 아님)
     *  (여기서 빈으로 만든 부분들은 여러 위치에서 DI하는 용도로 만든 것임)
     */
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 메모리 방식 인증처리
//        String password = passwordEncoder().encode("1111");
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER","MANAGER","ADMIN");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER","ADMIN");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");

        // DB 정보를 통한 인증처리
//        auth.userDetailsService(customUserDetailsService);

        auth.authenticationProvider(authenticationProvider());

    }

    // 정적파일은 security 필터 거치지 않게 설정
    // permitAll은 필터에서 허용여부를 판단하지만 얘는 필터 밖에 있음.
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .antMatchers("/", "/users", "user/login/**", "/login*").permitAll()
//                .antMatchers(HttpMethod.GET,"/config").hasRole("ADMIN")  // 이런식으로 http method도 설정 가능
                .anyRequest().authenticated()
        ;

        http
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                // 순서 조심 : API 설정이 아래에 위치할 수록 위에 위치한 설정을 덮어쓰게 됨. 따라서 defaultSuccessUrl이 아래에 있으면 제대로 동작 안함
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
        ;

        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        ;

    }

    // 평문인 비밀번호를 암호화
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // 기본이 bcrypt
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(customUserDetailsService, passwordEncoder());
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

}
