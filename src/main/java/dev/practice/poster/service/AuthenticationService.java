package dev.practice.poster.service;

import dev.practice.poster.dto.LoginRequestDTO;
import dev.practice.poster.dto.LoginResponseDTO;
import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.model.CustomUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Transactional
@Service
public class AuthenticationService {

    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final TokenService tokenService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService (
            UserService userService,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            AuthenticationManager authenticationManager
    ){
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

    public CustomUser registerUser(UserDTO userDTO){
        String encodedPassword = passwordEncoder.encode(userDTO.getPassword());

        return userService.save(new UserDTO(userDTO.getUsername(),
                encodedPassword,
                userDTO.getRoles()));
    }

    public LoginResponseDTO loginUser(Authentication authentication){

        log.info(AuthenticationService.class.getName() + " start login of " + authentication.getName());

        try {
            String token = tokenService.generateJwt(authentication);

            return new LoginResponseDTO(
                    userService.findUser(authentication.getName()), token);
        }catch (AuthenticationException e){
            return null;
        }
    }
}
