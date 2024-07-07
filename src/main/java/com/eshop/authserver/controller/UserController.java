package com.eshop.authserver.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.eshop.authserver.entities.AuthUser;
import com.eshop.authserver.repository.AuthUserRepository;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;



@RestController
public class UserController {

    @Autowired
    private AuthUserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity registerUser(@RequestBody AuthUser user) {
        try{
            if(userRepository.findByUsername(user.getUsername().toLowerCase()).isPresent()) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists.");
            } 
            user.setPwd(passwordEncoder.encode(user.getPwd()));
            AuthUser savedUser = userRepository.save(user);

            return ResponseEntity.status(HttpStatus.OK).body("User registered successfully.");
        } catch(Exception e){
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    @GetMapping("/greetUser")
    public String greetUser() {
        return "Welcome user";
    }
    
}
