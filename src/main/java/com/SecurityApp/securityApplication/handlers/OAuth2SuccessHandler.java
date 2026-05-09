package com.SecurityApp.securityApplication.handlers;

import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.services.JWTService;
import com.SecurityApp.securityApplication.services.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();

        String githubUsername = oAuth2User.getAttribute("login");
        String name = oAuth2User.getAttribute("name");
        String email = oAuth2User.getAttribute("email");

        String fallbackId = githubUsername != null ? githubUsername : oAuth2User.getName();
        String resolvedEmail = email != null
                ? email
                : (fallbackId != null ? fallbackId + "@github.local" : null);
        String resolvedName = name != null
                ? name
                : (githubUsername != null ? githubUsername : "GitHub User");

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

        String frontendUrl = "https://localhost:8080/home.html?token=" + accessToken;
        getRedirectStrategy().sendRedirect(request, response, frontendUrl);
    }
}