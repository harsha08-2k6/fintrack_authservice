package com.spendwise.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HomeController {

    @GetMapping("/")
    public ResponseEntity<Map<String, String>> home() {
        return ResponseEntity.ok(Map.of(
            "service", "FinTrack Auth Service",
            "status", "UP",
            "message", "Auth Service is running and connected to Eureka!"
        ));
    }
}

