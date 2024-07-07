package com.eshop.authserver.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.eshop.authserver.entities.AuthUser;

@Repository
public interface AuthUserRepository extends MongoRepository<AuthUser, String>{
    public Optional<AuthUser> findByUsername(String username);
}
