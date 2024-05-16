package com.ssobackend.SSO.repository;

import com.ssobackend.SSO.model.MyUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MyUserRepository extends JpaRepository<MyUser, Integer> {

    Optional<MyUser> findByUsername(String username);
}
