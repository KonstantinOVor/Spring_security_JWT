package com.example.Spring_security_JWT.dto;

import lombok.Data;

@Data
public class RegistrationUserDto {
    private String username;
    private String password;
    private String confirmPassword;
    private String email;
}
