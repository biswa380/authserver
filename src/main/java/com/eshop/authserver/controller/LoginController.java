package com.eshop.authserver.controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;


@RestController
public class LoginController {
    // @CrossOrigin(origins = "http://localhost:4200")
    // @GetMapping("/login")
    // public String login() {
    //     return "login";
    // }
    
    @GetMapping("/login/oauth2/code/web-client")
    public String getCode(@RequestParam("code") String code) {
        return code;
    }
}
