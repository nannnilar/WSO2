package com.example.wso2_integration.record;

import java.util.List;

public record UserRequest(
        String username, String password, String email, String phone, List<String> roles) {
}
