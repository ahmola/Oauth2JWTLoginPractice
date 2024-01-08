package dev.practice.poster.controller;

import dev.practice.poster.model.CustomUser;
import dev.practice.poster.service.AuthenticationService;
import dev.practice.poster.service.TokenService;
import dev.practice.poster.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserService userService;

    private final AuthenticationService authenticationService;

    private final PasswordEncoder passwordEncoder;

    public AdminController(
            UserService userService,
            AuthenticationService authenticationService,
            PasswordEncoder passwordEncoder){
        this.userService = userService;
        this.authenticationService = authenticationService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/users")
    public ResponseEntity<List<CustomUser>> showAllUsers(Authentication authentication){
        log.info(AdminController.class.getName() + " get request for showAllUsers from "
                + authentication.getName());

        return new ResponseEntity<>(userService.findAll(), HttpStatus.OK);
    }
}
