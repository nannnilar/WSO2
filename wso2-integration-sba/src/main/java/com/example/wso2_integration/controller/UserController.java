package com.example.wso2_integration.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/public/hello")
    public String hello() {
        return "Public ok";
    }

    @GetMapping("/user/info")
    public Map<String, Object> info(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "username", jwt.getClaimAsString("preferred_username"),
                "email", jwt.getClaimAsString("email"),
                "phone", jwt.getClaimAsString("phone_number"),
                "roles", jwt.getClaimAsStringList("groups")
        );
    }

    @GetMapping("/admin/secret")
    @PreAuthorize("hasRole('admin')")
    public String admin() {
        return "Admin OK";
    }

    @GetMapping("/user/dashboard")
    @PreAuthorize("hasRole('user')")
    public String userDashboard() {
        return "User OK";
    }
}
