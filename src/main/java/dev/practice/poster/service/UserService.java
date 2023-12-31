package dev.practice.poster.service;

import dev.practice.poster.config.authenticaion.CustomAuthenticationManager;
import dev.practice.poster.dto.LoginResponseDTO;
import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.model.CustomUser;
import dev.practice.poster.model.Role;
import dev.practice.poster.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@Slf4j
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    private final CustomAuthenticationManager customAuthenticationManager;

    private final TokenService tokenService;

    public UserService(UserRepository userRepository,
                       CustomAuthenticationManager customAuthenticationManager,
                       TokenService tokenService){
        this.userRepository = userRepository;
        this.customAuthenticationManager = customAuthenticationManager;
        this.tokenService = tokenService;
    }

    public void save(UserDTO userDTO){
        log.info("Create " + userDTO.toString());
        userRepository.save(new CustomUser(userDTO));
    }

    public UserDetails findUser(String username){
        log.info("Finding User... : " + username);

        return userRepository.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException(username + " not found"));
    }

    public List<Role> findRoles(String username){
        log.info("Finding Roles... : "+ username);

        return userRepository.findRolesByUsername(username).get(0);
    }

    public boolean deleteUser(String username){
        log.info("Deleting User... : " + username);

        userRepository.deleteByUsername(username);

        return true;
    }

    @Override
    public UserDetails loadUserByUsername(String username){
        log.info("Loading user : " + username);

        return userRepository.findByUsername(username)
                .orElseThrow(()-> new NoSuchElementException(username + " not found"));
    }

    public LoginResponseDTO loginUser(String username, String password, HttpSecurity http){

        try{
            Authentication authentication = customAuthenticationManager.authenticationManager(http).authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            String token = tokenService.generateJwt(authentication);

            return new LoginResponseDTO(
                    userRepository.findByUsername(username).orElseThrow(
                            ()-> new NoSuchElementException(username + " not found"))
                    ,token);
        }catch (Exception e) {
            return new LoginResponseDTO(null, "");
        }
    }
}
