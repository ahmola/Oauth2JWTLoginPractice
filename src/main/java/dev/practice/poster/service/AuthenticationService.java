package dev.practice.poster.service;

import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.model.CustomUser;
import dev.practice.poster.model.Role;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Transactional
@Service
public class AuthenticationService {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    public AuthenticationService (
            UserService userService,
            PasswordEncoder passwordEncoder
    ){
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public CustomUser registerUser(UserDTO userDTO){
        String encodedPassword = passwordEncoder.encode(userDTO.getPassword());

        return userService.save(new UserDTO(userDTO.getUsername(),
                encodedPassword,
                userDTO.getRoles()));
    }
}
