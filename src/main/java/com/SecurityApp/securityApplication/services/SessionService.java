package com.SecurityApp.securityApplication.services;

import com.SecurityApp.securityApplication.entities.Session;
import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.repositories.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;

    private static final int MAX_SESSIONS_PER_USER = 5;

    @Transactional
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

    // Throws if the refresh token does not belong to an active session (e.g. logged out or evicted).
    @Transactional
    public Session validateSession(String refreshToken) {
        Session session = sessionRepository
                .findByRefreshToken(refreshToken)
                .orElseThrow(() -> new BadCredentialsException("Session expired or invalid, please login again"));
        session.setLastUsedAt(new Date());
        return sessionRepository.save(session);
    }

    // Refresh token rotation: the old token stops working once a new one is issued.
    @Transactional
    public void rotateRefreshToken(Session session, String newRefreshToken) {
        session.setRefreshToken(newRefreshToken);
        session.setLastUsedAt(new Date());
        sessionRepository.save(session);
    }

    @Transactional
    public void deleteSession(String refreshToken) {

        sessionRepository.findByRefreshToken(refreshToken)
                .ifPresent(sessionRepository::delete);
    }

    public List<Session> getUserSessions(User user) {

        return sessionRepository.findByUser(user);
    }
}
