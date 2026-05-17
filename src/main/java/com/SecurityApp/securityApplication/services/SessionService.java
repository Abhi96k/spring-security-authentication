package com.SecurityApp.securityApplication.services;

import com.SecurityApp.securityApplication.entities.Session;
import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.repositories.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;
    private final int MAX_SESSIONS_PER_USER = 5;


    public Void generateNewSession(User user, String refreshToken) {
        List<Session> userSession = sessionRepository.findByUser(user);

        if(userSession.size() == MAX_SESSIONS_PER_USER) {
            userSession.sort(Comparator.comparing(Session::getCreationDate));

            Session leastRecentlyUsedSession = userSession.getFirst();
            sessionRepository.delete(leastRecentlyUsedSession);
        }


    }
}
