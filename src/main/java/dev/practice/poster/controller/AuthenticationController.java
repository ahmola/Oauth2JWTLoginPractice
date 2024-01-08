package dev.practice.poster.controller;

import dev.practice.poster.dto.LoginRequestDTO;
import dev.practice.poster.dto.LoginResponseDTO;
import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.model.CustomUser;
import dev.practice.poster.service.AuthenticationService;
import dev.practice.poster.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final UserService userService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(
            UserService userService,
            AuthenticationService authenticationService
    ){
        this.userService = userService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserDTO userDTO){
        log.info("Receive " + userDTO.toString() + " to Register");

        CustomUser result = authenticationService.registerUser(userDTO);

        return new ResponseEntity<>(result.toString() + " is Created", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(Authentication authentication){
        log.info(AuthenticationController.class.getName()
                + " gets request login for " + authentication.toString());

        return new ResponseEntity<>(
                authenticationService.loginUser(authentication),
                HttpStatus.ACCEPTED);
    }
}
