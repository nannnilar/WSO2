package com.example.wso2_integration.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorHandlingController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        Object message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        Object path = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);

        model.addAttribute("status", status);
        model.addAttribute("error", message != null ? message : "N/A");
        model.addAttribute("message", message != null ? message : "N/A");
        model.addAttribute("path", path != null ? path : "N/A");

        return "error";
    }
}
