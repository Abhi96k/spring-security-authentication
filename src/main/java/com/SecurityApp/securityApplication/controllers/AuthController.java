package com.SecurityApp.securityApplication.controllers;

import com.SecurityApp.securityApplication.dto.LoginDto;
import com.SecurityApp.securityApplication.dto.LoginResponseDto;
import com.SecurityApp.securityApplication.dto.SignUpDto;
import com.SecurityApp.securityApplication.dto.UserDto;
import com.SecurityApp.securityApplication.services.AuthService;
import com.SecurityApp.securityApplication.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final AuthService authService;

    // "/singup" kept for backward compatibility with existing clients
    @PostMapping({"/signup", "/singup"})
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<UserDto> signUp(@RequestBody SignUpDto signUpDto) {
        UserDto userDto = userService.signUp(signUpDto);
        return ResponseEntity.ok(userDto);
    }



    @PostMapping("/login")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto loginDto,
                                        HttpServletResponse response ) {
        LoginResponseDto loginResponseDto = authService.login(loginDto);
        response.addCookie(refreshCookie(loginResponseDto.getRefreshToken(), -1));
        return ResponseEntity.ok(loginResponseDto);
    }


    // Public on purpose: clients call this once the access token has expired.
    // The refresh token in the HttpOnly cookie is the credential.
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = readRefreshToken(request);
        if (refreshToken == null) {
            throw new BadCredentialsException("Refresh token not found in cookies");
        }
        LoginResponseDto loginResponseDto = authService.refreshToken(refreshToken);
        response.addCookie(refreshCookie(loginResponseDto.getRefreshToken(), -1));
        return ResponseEntity.ok(loginResponseDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(readRefreshToken(request));
        response.addCookie(refreshCookie("", 0));
        return ResponseEntity.noContent().build();
    }

    private String readRefreshToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    private Cookie refreshCookie(String value, int maxAge) {
        Cookie cookie = new Cookie("refreshToken", value);
        cookie.setHttpOnly(true); // not readable from JavaScript
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        return cookie;
    }

}
