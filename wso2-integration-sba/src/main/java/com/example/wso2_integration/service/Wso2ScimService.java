package com.example.wso2_integration.service;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
public class Wso2ScimService {

    private final WebClient client;

    public Wso2ScimService(WebClient.Builder builder) {
        this.client = builder
                .baseUrl("https://localhost:9443/scim2")
                .defaultHeaders(headers -> {
                    String auth = Base64.getEncoder().encodeToString("admin:admin".getBytes());
                    headers.set("Authorization", "Basic " + auth);
                })
                .build();
    }

    public Map createUser(String username, String password, String email, String phone, List<String> roles) {

        var body = Map.of(
                "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:User"),
                "userName", username,
                "password", password,
                "emails", List.of(Map.of("value", email, "primary", true)),
                "phoneNumbers", List.of(Map.of("value", phone, "primary", true)),
                "roles", roles.stream().map(r -> Map.of("value", r)).toList()
        );

        return client.post()
                .uri("/Users")
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }
}
