package com.SecurityApp.securityApplication.config;

import com.SecurityApp.securityApplication.entities.enums.Permission;
import com.SecurityApp.securityApplication.entities.enums.Role;
import com.SecurityApp.securityApplication.filters.JwtAuthFilter;
import com.SecurityApp.securityApplication.handlers.OAuth2SuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    // Public APIs
    private static final String[] PUBLIC_ENDPOINTS = {
            "/auth/**",
            "/api/auth/**",
            "/oauth2/**",
            "/login/**"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        http

                /*
                 Disable CSRF because:
                 - We use JWT
                 - Stateless REST APIs
                */
                .csrf(AbstractHttpConfigurer::disable)

                /*
                 Session Policy

                 OAuth2 needs temporary session support
                 during authorization flow.
                */
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.IF_REQUIRED
                        )
                )

                /*
                 Authorization Rules
                */
                .authorizeHttpRequests(auth -> auth

                        /*
                         Public APIs
                        */
                        .requestMatchers(PUBLIC_ENDPOINTS)
                        .permitAll()

                        /*
                         Admin Role APIs

                         hasRole("ADMIN")
                         internally checks:

                         ROLE_ADMIN
                        */
                        .requestMatchers("/admin/**")
                        .hasRole(Role.ADMIN.name())

                        /*
                         Permission Based APIs
                        */

                        // Read Post
                        .requestMatchers(
                                HttpMethod.GET,
                                "/posts/**"
                        )
                        .hasAuthority(Permission.POST_VIEW.name())

                        // Create Post
                        .requestMatchers(
                                HttpMethod.POST,
                                "/posts/**"
                        )
                        .hasAuthority(Permission.POST_CREATE.name())

                        // Delete Post
                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/posts/**"
                        )
                        .hasAuthority(Permission.POST_DELETE.name())

                        /*
                         Any other request
                         must be authenticated
                        */
                        .anyRequest()
                        .authenticated()
                )

                /*
                 Basic Authentication
                 Optional for testing
                */
                .httpBasic(Customizer.withDefaults())

                /*
                 OAuth2 Login
                */
                .oauth2Login(oauth2 -> oauth2

                        .successHandler(oAuth2SuccessHandler)

                        .failureUrl("/login?error=true")
                );

        /*
         Add JWT Filter before
         UsernamePasswordAuthenticationFilter

         So JWT validation happens first
        */
        http.addFilterBefore(
                jwtAuthFilter,
                UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }

    /*
     Authentication Manager Bean
    */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config
    ) throws Exception {

        return config.getAuthenticationManager();
    }
}
