package com.example.Spring_security_JWT.security.config;

import com.example.Spring_security_JWT.security.filter.JwtAuthenticationFilter;
import com.example.Spring_security_JWT.security.provider.JwtAuthenticationProvider;
import com.example.Spring_security_JWT.service.impl.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserServiceImpl userService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(jwtAuthenticationProvider)
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                                .requestMatchers("/admin").hasRole("ADMIN")
                                .requestMatchers("/secured").authenticated()
                                .requestMatchers("/login").anonymous()
                                .anyRequest().permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .permitAll()
                )
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        .expiredUrl("/login")
                );

        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userService);
        return daoAuthenticationProvider;
    }
}