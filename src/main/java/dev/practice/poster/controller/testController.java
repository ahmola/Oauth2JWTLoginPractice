package dev.practice.poster.controller;

import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/test")
public class testController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public testController(UserService userService,
                          PasswordEncoder passwordEncoder){
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public String defaultTest(Authentication authentication){

        return "hello " + authentication.getName();
    }

    @GetMapping("/roles/{username}")
    public ResponseEntity<String> showRoles(@PathVariable(value = "username") String username){
        log.info("Start Finding " + username + "'s roles");

        return new ResponseEntity<>(
                userService.findRoles(username).toString(), HttpStatus.FOUND);
    }

    @PostMapping("/post")
    public ResponseEntity<String> postUser(@RequestBody UserDTO userDTO){
        log.info("Start Saving " + userDTO.getUsername());

        userDTO.setPassword(passwordEncoder
                .encode(userDTO.getPassword()));

        userService.save(userDTO);

        return new ResponseEntity<>(
                userDTO.getUsername() + " is Created", HttpStatus.CREATED);
    }

    @DeleteMapping("/delete/{username}")
    public ResponseEntity<Boolean> deleteUser(@PathVariable("username") String username){
        log.info("Start deleting " + username);

        boolean result = userService.deleteUser(username);

        return new ResponseEntity<>(result, HttpStatus.OK);
    }
}
