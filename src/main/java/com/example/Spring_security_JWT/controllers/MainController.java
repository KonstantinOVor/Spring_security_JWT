package com.example.Spring_security_JWT.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequiredArgsConstructor
public class MainController {

    @GetMapping("/secured")
    public ResponseEntity<String> securedData() {

        return ResponseEntity.ok().body("Защищенные данные");
    }

    @GetMapping("/admin")
    public ResponseEntity<String> adminData() {

        return ResponseEntity.ok().body("Административные данные");
    }

    @GetMapping("/info")
    public ResponseEntity<String> userData(Principal principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Неавторизованный доступ");
        }
        return ResponseEntity.ok().body(principal.getName());
    }
}
