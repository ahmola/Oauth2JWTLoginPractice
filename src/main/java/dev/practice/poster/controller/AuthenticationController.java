package dev.practice.poster.controller;

import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.model.CustomUser;
import dev.practice.poster.service.AuthenticationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth/api")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(
            AuthenticationService authenticationService
    ){
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserDTO userDTO){
        log.info("Receive " + userDTO.toString() + " to Register");

        CustomUser result = authenticationService.registerUser(userDTO);

        return new ResponseEntity<>(result.toString() + " is Created", HttpStatus.CREATED);
    }
}
