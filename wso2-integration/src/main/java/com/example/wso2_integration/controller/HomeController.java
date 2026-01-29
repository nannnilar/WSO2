package com.example.wso2_integration.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Map;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Model model, @AuthenticationPrincipal OidcUser oidcUser) {
        if (oidcUser != null) {
            // Use actual claim names from WSO2
            model.addAttribute("userName", oidcUser.getClaim("username"));
            model.addAttribute("org_name", oidcUser.getClaim("org_name"));
            List<String> roles = oidcUser.getClaimAsStringList("roles");
            model.addAttribute("roles", roles);
            model.addAttribute("phone_number",oidcUser.getClaim("phone_number"));
            System.out.println("User Claims "+ oidcUser.getClaims());
            return "home";
        }
        return "redirect:/oauth2/authorization/wso2";
    }

    @GetMapping("/admin")
    public String adminPage() {
        return "admin"; // only admin role can access
    }

    @GetMapping("/user")
    public String userPage() {
        return "user"; // user or admin role
    }

    @GetMapping("/userinfo")
    @ResponseBody
    public Map<String, Object> userinfo(@AuthenticationPrincipal OidcUser oidcUser) {
        return oidcUser.getClaims(); // this may include roles if configured
    }

    @GetMapping("/token")
    @ResponseBody
    public String token(@AuthenticationPrincipal OidcUser oidcUser) {
        return oidcUser.getIdToken().getTokenValue(); // raw JWT
    }

    @GetMapping("/secured")
    public String secured(Model model, @AuthenticationPrincipal OidcUser oidcUser) {
        model.addAttribute("user", oidcUser);
        return "secured";
    }

    @GetMapping("/debug")
    public String debug(@AuthenticationPrincipal OidcUser oidcUser, Model model) {
        model.addAttribute("claims", oidcUser.getClaims());
        return "debug";
    }

}
