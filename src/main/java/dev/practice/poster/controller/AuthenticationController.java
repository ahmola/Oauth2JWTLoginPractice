package dev.practice.poster.controller;

import dev.practice.poster.config.SecurityConfig;
import dev.practice.poster.dto.LoginResponseDTO;
import dev.practice.poster.service.TokenService;
import dev.practice.poster.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/auth/api")
public class AuthenticationController {

    @Autowired
    private HttpSecurity http;

    @Autowired
    private UserService userService;

    @Autowired
    private TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody LoginResponseDTO body){

        userService.loginUser(body.getUser().getUsername(), body.getUser().getPassword(), http);

        return new ResponseEntity<>(body.toString() + " is logged in!",
                HttpStatus.ACCEPTED);
    }
}
