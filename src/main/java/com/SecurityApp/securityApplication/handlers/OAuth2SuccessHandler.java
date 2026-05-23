package com.SecurityApp.securityApplication.handlers;

import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.services.JWTService;
import com.SecurityApp.securityApplication.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;


@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTService jwtService;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) throws IOException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();

        Object githubUsernameAttribute = oAuth2User.getAttribute("login");
        String githubUsername = githubUsernameAttribute != null ? githubUsernameAttribute.toString() : null;
        Object nameAttribute = oAuth2User.getAttribute("name");
        String name = nameAttribute != null ? nameAttribute.toString() : null;
        Object emailAttribute = oAuth2User.getAttribute("email");
        String email = emailAttribute != null ? emailAttribute.toString() : null;

        String fallbackId = githubUsername != null ? githubUsername : oAuth2User.getName();
        String resolvedEmail = email != null ? email : fallbackId + "@github.local";
        String resolvedName = name != null
                ? name
                : (githubUsername != null ? githubUsername : "GitHub User");

        if (resolvedEmail == null || resolvedEmail.isBlank()) {
            throw new IllegalArgumentException("OAuth user email is required");
        }

        User user = userService.getOrCreateOAuthUser(resolvedEmail, resolvedName);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        response.setHeader("Authorization", "Bearer " + accessToken);

        log.info("GitHub Username: {}", githubUsername);
        log.info("Name: {}", resolvedName);
        log.info("Email: {}", resolvedEmail);

        String frontendUrl = "http://localhost:8080/home.html?token=" + accessToken;
        getRedirectStrategy().sendRedirect(request, response, frontendUrl);
    }
}