package com.securiy.realsecurity.provider;

import com.securiy.realsecurity.common.FormWebAuthenticationDetails;
import com.securiy.realsecurity.domain.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;


@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * 인증에 대한 검증 부분
     * - authentication : 사용자가 입력한 아이디, pw 등이 담겨있음
     * - id, pw 외 다른 검증도 추가할 수 있다.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) customUserDetailsService.loadUserByUsername(username);

        // 입력한 패스워드와 DB상의 패스워드 일치 여부
        if (!passwordEncoder.matches(password, accountContext.getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        // secretKey 검증
        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = details.getSecretKey();
        if (!"secret".equals(secretKey)) {
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }

        // 최종적으로 인증에 성공한 정보를 담아 Provider를 호출한 AuthenticationProcessingFilter에게 반환
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
        return authenticationToken;
    }

    /**
     * 파라미터로 넘어온 authentication이 UsernamePasswordAuthenticationToken과 일치하면
     * CustomAuthenticationProvider가 인증을 처리한다.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
