package com.example.Spring_security_JWT.controllers;

import com.example.Spring_security_JWT.dto.JwtRequest;
import com.example.Spring_security_JWT.dto.JwtResponse;
import com.example.Spring_security_JWT.exceptions.AppError;
import com.example.Spring_security_JWT.security.util.JwtUtil;
import com.example.Spring_security_JWT.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;


    @PostMapping("/login")
    public ResponseEntity<?> createAuthToken(@RequestBody JwtRequest authRequest) {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<> (new AppError(HttpStatus.UNAUTHORIZED.value(),
                    "Неправильное имя пользователя или пароль"), HttpStatus.UNAUTHORIZED);
        }
        UserDetails userDetails = userService.loadUserByUsername(authRequest.getUsername());
        String token = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponse(token));
    }
}
