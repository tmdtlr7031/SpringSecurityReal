package com.securiy.realsecurity.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    // successHandler, FailureHandler 둘 다 super.onAuthenticationFailure가 없어도 무방하나
    // Fail쪽은 부모 객체로 처리 넘기는게 편해서 남겨둠. 나중에 상위 객체 흐름 보면 도움될 듯
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Invaild Username or Password";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invaild Username or Password";
        }else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invaild Secret Key";
        }

        setDefaultFailureUrl("/login?error=true&exception="+errorMessage);

        super.onAuthenticationFailure(request, response, exception);
    }
}
