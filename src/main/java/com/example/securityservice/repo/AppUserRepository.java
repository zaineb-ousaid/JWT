package com.example.securityservice.repo;

import com.example.securityservice.entities.AppRole;
import com.example.securityservice.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {

    AppUser findByUsername(String username);
}
