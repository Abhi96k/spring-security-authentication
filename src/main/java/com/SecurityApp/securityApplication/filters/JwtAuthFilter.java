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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.List;

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
            final String requestTokenHeader =
                    request.getHeader("Authorization");

            // No token present: keep whatever authentication (if any) is already in the context
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

            // May throw UsernameNotFoundException.
            // Uses the unsecured lookup: no principal is authenticated yet at this point.
            User user = userService.findUserById(userId);

            // we can extrat the roles from the user entity and set them in the authentication token
            // already we have flow we are generating tokens with user roles, so we can extract the roles from the token and set them in the authentication token
            List<String> roles =
                    jwtService.getRolesFromToken(token);

            if (roles == null) {
                roles = List.of();
            }

            List<SimpleGrantedAuthority> authorities =
                    roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            authorities
                    )
            );

            filterChain.doFilter(request, response);

        } catch (Exception ex) {

            // Forward exception to GlobalExceptionHandler
            if (handlerExceptionResolver.resolveException(
                    request,
                    response,
                    null,
                    ex
            ) == null) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            }
        }
    }
}

