package com.example.Spring_security_JWT.dto;
import lombok.Data;

@Data
public class JwtRequest {
    private String username;
    private String password;

}
