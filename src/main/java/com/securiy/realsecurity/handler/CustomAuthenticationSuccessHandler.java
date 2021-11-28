package com.securiy.realsecurity.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // 미인증 사용자가 접근했던 url정보 담고 있음.
    // HttpSessionRequestCache는 DefaultSavedRequest(SavedRequest 기본 구현체) 를 세션에 저장하는 역할
    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 기본 Redirect Url 설정
        // SecurityConfig에서 defaultSuccessUrl("/")이 되어있다면 생략 가능
        setDefaultTargetUrl("/");

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        // null인 경우도 있음 (ex. 인증 전 다른 자원 접근 -> 인증 예외 발생 -> 로그인페이지 온 경우 savedRequest 없음)
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        }else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
