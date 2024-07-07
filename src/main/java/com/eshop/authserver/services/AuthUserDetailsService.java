package com.eshop.authserver.services;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.eshop.authserver.entities.AuthUser;
import com.eshop.authserver.repository.AuthUserRepository;

@Service
public class AuthUserDetailsService implements UserDetailsService{

    @Autowired
    private AuthUserRepository authUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<AuthUser> user = authUserRepository.findByUsername(username.toLowerCase());
        if(!user.isPresent()) {
            throw new UsernameNotFoundException(username);
        } else {
            return User.builder()
            .username(user.get().getUsername())
            .password(user.get().getPwd())
            .disabled(!user.get().getIsActive())
            .build();
        }
    }

}
