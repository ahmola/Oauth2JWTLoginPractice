package dev.practice.poster.service;

import dev.practice.poster.dto.LoginResponseDTO;
import dev.practice.poster.dto.UserDTO;
import dev.practice.poster.model.CustomUser;
import dev.practice.poster.model.Role;
import dev.practice.poster.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    public CustomUser save(UserDTO userDTO){
        log.info("Create " + userDTO.toString());
        return userRepository.save(new CustomUser(userDTO));
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
}
