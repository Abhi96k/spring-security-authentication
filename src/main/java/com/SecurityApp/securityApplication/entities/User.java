package com.SecurityApp.securityApplication.entities;

import com.SecurityApp.securityApplication.entities.enums.Permission;
import com.SecurityApp.securityApplication.entities.enums.Role;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

@Entity
@Getter
@Setter
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles;


    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Permission> permissions;

    @Override
    public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();

        if (roles != null) {
            roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                    .forEach(authorities::add);
        }

        if (permissions != null) {
            permissions.stream()
                    .map(permission -> new SimpleGrantedAuthority(permission.name()))
                    .forEach(authorities::add);
        }

        return authorities;
    }

    @Override
    public @Nullable String getPassword() {
        return this.password;
    }

    @Override
    public @NonNull String getUsername() {
        return this.email;
    }
}