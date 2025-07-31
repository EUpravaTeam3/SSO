package com.ssobackend.SSO.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginDemoController {
    @GetMapping("/login")
    public String handleLogin() {
        return "custom_login";
    }
}
