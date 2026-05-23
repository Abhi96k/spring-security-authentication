package com.SecurityApp.securityApplication.services;

import com.SecurityApp.securityApplication.entities.Session;
import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.repositories.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;

    private static final int MAX_SESSIONS_PER_USER = 5;

    public void generateNewSession(User user, String refreshToken) {
        List<Session> userSessions = sessionRepository.findByUser(user);
        if (userSessions.size() >= MAX_SESSIONS_PER_USER) {
            userSessions.sort(Comparator.comparing(Session::getCreationDate));
            Session oldestSession = userSessions.get(0);
            sessionRepository.delete(oldestSession);
        }

        Session newSession = Session.builder()
                .user(user)
                .refreshToken(refreshToken)
                .build();

        sessionRepository.save(newSession);
    }

    public boolean validateSession(String refreshToken) {
        return sessionRepository
                .findByRefreshToken(refreshToken)
                .map(session -> {
                    session.setLastUsedAt(new Date());
                    sessionRepository.save(session);
                    return true;
                })
                .orElse(false);

    }

    public void deleteSession(String refreshToken) {

        sessionRepository.findByRefreshToken(refreshToken)
                .ifPresent(sessionRepository::delete);
    }

    public List<Session> getUserSessions(User user) {

        return sessionRepository.findByUser(user);
    }
}