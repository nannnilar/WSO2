package com.example.wso2_integration.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class ConfigSecurity {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/css/**", "/js/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("APP_ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER","APP_ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                // ✅ use the injected bean instead of calling this.oidcUserService()
                                .oidcUserService(oidcUserService)
                        )
                        .defaultSuccessUrl("/", true)
                )
                .logout(logout -> logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            // Redirect to WSO2 logout
                            String logoutUrl = "https://localhost:9444/oidc/logout?post_logout_redirect_uri=http://localhost:9090/";
                            response.sendRedirect(logoutUrl);
                        })
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                );


        return http.build();
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        System.out.println("OidcUserService: "  + delegate.getClass().getName() );
        return userRequest -> {
            System.out.println("OidcUserService called!" + delegate.getClass().getName() );
            OidcUser oidcUser = delegate.loadUser(userRequest);

            List<GrantedAuthority> mappedAuthorities = new ArrayList<>(oidcUser.getAuthorities());
            List<String> roles = oidcUser.getClaimAsStringList("roles");

            System.out.println("Roles from WSO2: " + roles);

            if (roles != null) {
                mappedAuthorities.addAll(
                        roles.stream()
                                .filter(r -> !r.isBlank())
                                .map(r -> "ROLE_" + r.toUpperCase()) // add ROLE_ prefix
                                .map(SimpleGrantedAuthority::new)
                                .toList()
                );
            }

            return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
        };
    }

}
