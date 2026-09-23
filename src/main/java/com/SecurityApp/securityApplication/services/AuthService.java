package com.SecurityApp.securityApplication.services;


import com.SecurityApp.securityApplication.dto.LoginDto;
import com.SecurityApp.securityApplication.dto.LoginResponseDto;
import com.SecurityApp.securityApplication.entities.Session;
import com.SecurityApp.securityApplication.entities.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    private final UserService userService;
    private final SessionService sessionService;


    @PreAuthorize("isAnonymous()")
    public LoginResponseDto login(LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDto.getEmail(),
                        loginDto.getPassword()
                )
        );

        User user = (User) authentication.getPrincipal();

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        sessionService.generateNewSession(user, refreshToken);



        return new LoginResponseDto(user.getId(), accessToken, refreshToken);


    }

    // No @PreAuthorize here: the access token has usually expired when a client refreshes,
    // so the caller is anonymous. The refresh token itself is the credential.
    public LoginResponseDto refreshToken(String refreshToken) {
        // Extract userId from the refresh token (throws JwtException if invalid or expired)
        Long userId = jwtService.getUserIdFromToken(refreshToken);

        Session session = sessionService.validateSession(refreshToken);

        // Fetch user from database
        User user = userService.findUserById(userId);

        // Generate new tokens
        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        sessionService.rotateRefreshToken(session, newRefreshToken);

        return new LoginResponseDto(user.getId(), newAccessToken, newRefreshToken);
    }

    public void logout(String refreshToken) {
        if (refreshToken != null) {
            sessionService.deleteSession(refreshToken);
        }
    }
}
