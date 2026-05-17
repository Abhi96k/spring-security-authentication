package com.SecurityApp.securityApplication.repositories;

import com.SecurityApp.securityApplication.entities.Session;
import com.SecurityApp.securityApplication.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SessionRepository extends JpaRepository<Session, Long> {

    List<Session> findByUser(User user);
}
