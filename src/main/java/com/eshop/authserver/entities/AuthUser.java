package com.eshop.authserver.entities;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Builder;
import lombok.Data;

@Data
@Document
@Builder
public class AuthUser {
    @Id
    public String id;
    @Indexed
    public String username;
    public String pwd;
    public String firstName;
    public String lastName;
    public Boolean isActive;
}
