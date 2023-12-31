package dev.practice.poster.config.authenticaion;

import dev.practice.poster.config.CustomPasswordEncoder;
import dev.practice.poster.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Slf4j
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;
    private final CustomPasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(
            UserService userService,
            CustomPasswordEncoder passwordEncoder){
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        log.info("Start Authenticating");

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails user = userService.findUser(username);

        if(passwordEncoder.passwordEncoder()
                .matches(password, user.getPassword())){

            log.info("Authentication Succeed. Publish AuthenticationToken : " + user.getUsername());

            return new UsernamePasswordAuthenticationToken(
                    username,
                    password,
                    user.getAuthorities());
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
