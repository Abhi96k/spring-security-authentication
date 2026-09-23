package com.SecurityApp.securityApplication.bootstrap;

import com.SecurityApp.securityApplication.entities.PostEntity;
import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.entities.enums.Role;
import com.SecurityApp.securityApplication.repositories.PostRepository;
import com.SecurityApp.securityApplication.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

// Demo accounts and posts for local development (only with the "dev" profile)
@Slf4j
@Component
@Profile("dev")
@RequiredArgsConstructor
public class DevDataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PostRepository postRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        createUser("admin@example.com", "admin123", "Admin", Role.ADMIN);
        createUser("creator@example.com", "creator123", "Creator", Role.CREATOR);
        createUser("user@example.com", "user123", "Regular User", Role.USER);

        if (postRepository.count() == 0) {
            postRepository.save(new PostEntity(null, "Welcome", "This post was seeded by the dev profile."));
            postRepository.save(new PostEntity(null, "JWT + OAuth2", "Log in with email/password or GitHub to get a JWT."));
        }
        log.info("Dev data ready: admin@example.com/admin123, creator@example.com/creator123, user@example.com/user123");
    }

    private void createUser(String email, String password, String name, Role role) {
        if (userRepository.findByEmail(email).isPresent()) {
            return;
        }
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setName(name);
        user.setRoles(new HashSet<>(Set.of(role)));
        userRepository.save(user);
    }
}
