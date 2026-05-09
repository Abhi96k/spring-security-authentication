package com.SecurityApp.securityApplication.filters;

import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.services.JWTService;
import com.SecurityApp.securityApplication.services.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final UserService userService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    public JwtAuthFilter(
            JWTService jwtService,
            UserService userService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver
    ) {
        this.jwtService = jwtService;
        this.userService = userService;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            Authentication existingAuthentication =
                    SecurityContextHolder.getContext().getAuthentication();

            // If user already authenticated, skip JWT validation
            if (existingAuthentication != null
                    && existingAuthentication.isAuthenticated()
                    && !(existingAuthentication instanceof AnonymousAuthenticationToken)) {

                filterChain.doFilter(request, response);
                return;
            }

            final String requestTokenHeader =
                    request.getHeader("Authorization");

            // No token present
            if (requestTokenHeader == null ||
                    !requestTokenHeader.startsWith("Bearer ")) {

                filterChain.doFilter(request, response);
                return;
            }

            String token = requestTokenHeader.substring(7).trim();

            // Empty token
            if (token.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            // May throw JwtException
            Long userId = jwtService.getUserIdFromToken(token);

            if (userId == null) {
                filterChain.doFilter(request, response);
                return;
            }

            // May throw ResourceNotFoundException
            User user = userService.getUserById(userId);

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            user.getAuthorities()
                    )
            );

            filterChain.doFilter(request, response);

        } catch (Exception ex) {

            // Forward exception to GlobalExceptionHandler
            handlerExceptionResolver.resolveException(
                    request,
                    response,
                    null,
                    ex
            );
        }
    }
}