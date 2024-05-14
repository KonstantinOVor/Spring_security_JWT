package com.example.Spring_security_JWT.service;

import com.example.Spring_security_JWT.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;

public interface UserService {

    User createUser(User user);

    User getUserByUsername(String username);
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

    List<User> getAllUsers();

    void deleteUser(Long userId);
}

