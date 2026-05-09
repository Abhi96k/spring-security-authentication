package com.SecurityApp.securityApplication.services;

import com.SecurityApp.securityApplication.entities.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JWTServiceTest {

    private static final Logger log = LoggerFactory.getLogger(JWTServiceTest.class);

    private JWTService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JWTService();
        ReflectionTestUtils.setField(jwtService, "jwtSecretKey", "1234567890123456789012345678901234567890123456789012345678901234");
        ReflectionTestUtils.setField(jwtService, "expirationTime", 3_600_000L);
    }

    @Test
    void generateTokenAndExtractClaims_shouldReturnExpectedUserIdAndEmail() {
        User user = new User();
        user.setId(42L);
        user.setEmail("abhishek@example.com");
        user.setPassword("password");

        String token = jwtService.generateAccessToken(user);
        log.info("Generated JWT for {}: {}...", user.getEmail(), token.substring(0, 20));

        Long extractedUserId = jwtService.getUserIdFromToken(token);
        String extractedEmail = jwtService.getUserEmailFromToken(token);

        log.info("Extracted claims -> userId: {}, email: {}", extractedUserId, extractedEmail);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals(42L, extractedUserId);
        assertEquals("abhishek@example.com", extractedEmail);
    }
}
