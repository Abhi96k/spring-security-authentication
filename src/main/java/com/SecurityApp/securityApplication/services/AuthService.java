package com.SecurityApp.securityApplication.services;


import com.SecurityApp.securityApplication.dto.LoginDto;
import com.SecurityApp.securityApplication.dto.LoginResponseDto;
import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.exceptions.ResourceNotFoundException;
import com.SecurityApp.securityApplication.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTService jwtService;
    private final UserService userService;


    public LoginResponseDto login(LoginDto loginDto) {

        AuthenticationManager authenticationManager;

        try {
            authenticationManager = authenticationConfiguration.getAuthenticationManager();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to initialize AuthenticationManager", ex);
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDto.getEmail(),
                        loginDto.getPassword()
                )
        );

        User user = (User) authentication.getPrincipal();

        String accesToken = jwtService.generateAceessTolken(user);
        String refreshToken = jwtService.generateRefresghToken(user);

        return new LoginResponseDto(user.getId(), accesToken, refreshToken);


    }

    public LoginResponseDto refreshToken(String refreshToken) {
        // Extract userId from the refresh token
        Long userId = jwtService.getUserIdFromToken(refreshToken);

        // Fetch user from database
        User user = userService.getUserById(userId);

        // Generate new tokens
        String newAccessToken = jwtService.generateAceessTolken(user);
        String newRefreshToken = jwtService.generateRefresghToken(user);

        return new LoginResponseDto(user.getId(), newAccessToken, newRefreshToken);
    }
}
