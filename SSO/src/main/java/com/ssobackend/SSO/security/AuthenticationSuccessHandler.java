package com.ssobackend.SSO.security;

import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

import java.io.IOException;

public class AuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) {
            setDefaultTargetUrl("/admin/home");
//            setDefaultTargetUrl("http://localhost:8005/api"); for APR Service
        } else {
            setDefaultTargetUrl("/user/home");
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
