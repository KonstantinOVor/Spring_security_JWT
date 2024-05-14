package com.example.Spring_security_JWT.service.impl;

import com.example.Spring_security_JWT.model.Role;
import com.example.Spring_security_JWT.model.User;
import com.example.Spring_security_JWT.repository.RoleRepository;
import com.example.Spring_security_JWT.repository.UserRepository;
import com.example.Spring_security_JWT.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    public static final String ROLE_USER = "ROLE_USER";
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;


    @Override
    public User createUser(User user) {
        Role defaultRole = roleRepository.findByName(ROLE_USER).orElse(defaultRoleValue());
        user.setRoles(List.of(defaultRole));
        return userRepository.save(user);
    }

    private Role defaultRoleValue() {
        Role role = new Role();
        role.setName(ROLE_USER);
        return roleRepository.save(role);
    }


    @Override
    public User getUserByUsername(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        return user.orElse(null);

    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = getUserByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException(String.format("Пользователь %s не найден", username));
        }
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role.getName()))
                        .collect(Collectors.toList()));
    }
}
