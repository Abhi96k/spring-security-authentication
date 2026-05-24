package com.SecurityApp.securityApplication.utils;

import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.entities.enums.Permission;
import com.SecurityApp.securityApplication.entities.enums.Role;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public final class PermissionMapping {

    private static final Map<Role, Set<Permission>> ROLE_PERMISSIONS = Map.of(
            Role.USER, EnumSet.of(Permission.USER_VIEW, Permission.POST_VIEW),
            Role.CREATOR, EnumSet.of(
                    Permission.USER_VIEW,
                    Permission.POST_VIEW,
                    Permission.POST_CREATE,
                    Permission.POST_UPDATE
            ),
            Role.ADMIN, EnumSet.allOf(Permission.class)
    );

    private PermissionMapping() {
    }

    public static Set<SimpleGrantedAuthority> getAuthoritiesForRole(Role role) {
        if (role == null) {
            return Collections.emptySet();
        }

        Set<SimpleGrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));

        ROLE_PERMISSIONS.getOrDefault(role, Collections.emptySet())
                .forEach(permission ->
                        authorities.add(new SimpleGrantedAuthority(permission.name())));

        return Collections.unmodifiableSet(authorities);
    }

    public static Set<SimpleGrantedAuthority> getAuthoritiesForUser(User user) {
        if (user == null) {
            return Collections.emptySet();
        }

        Set<SimpleGrantedAuthority> authorities = new LinkedHashSet<>();

        if (user.getRoles() != null) {
            user.getRoles().forEach(role -> authorities.addAll(getAuthoritiesForRole(role)));
        }

        if (user.getPermissions() != null) {
            user.getPermissions().forEach(permission ->
                    authorities.add(new SimpleGrantedAuthority(permission.name())));
        }

        return Collections.unmodifiableSet(authorities);
    }
}
