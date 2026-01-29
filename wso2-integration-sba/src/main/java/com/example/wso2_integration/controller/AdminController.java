package com.example.wso2_integration.controller;

import com.example.wso2_integration.record.UserRequest;
import com.example.wso2_integration.service.Wso2ScimService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final Wso2ScimService scim;

    public AdminController(Wso2ScimService scim) {
        this.scim = scim;
    }

    @PostMapping("/create-user")
    public Object create(@RequestBody UserRequest req) {
        return scim.createUser(
                req.username(),
                req.password(),
                req.email(),
                req.phone(),
                req.roles()
        );
    }
}
