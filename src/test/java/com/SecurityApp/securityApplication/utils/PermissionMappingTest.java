package com.SecurityApp.securityApplication.utils;

import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.entities.enums.Permission;
import com.SecurityApp.securityApplication.entities.enums.Role;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionMappingTest {

    @Test
    void getAuthoritiesForRole_userShouldIncludeRoleAndUserPermissions() {
        Set<SimpleGrantedAuthority> authorities = PermissionMapping.getAuthoritiesForRole(Role.USER);

        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority(Permission.USER_VIEW.name())));
        assertTrue(authorities.contains(new SimpleGrantedAuthority(Permission.POST_VIEW.name())));
        assertEquals(3, authorities.size());
    }

    @Test
    void getAuthoritiesForRole_adminShouldIncludeAllPermissionsAndRole() {
        Set<SimpleGrantedAuthority> authorities = PermissionMapping.getAuthoritiesForRole(Role.ADMIN);

        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_ADMIN")));
        for (Permission permission : Permission.values()) {
            assertTrue(authorities.contains(new SimpleGrantedAuthority(permission.name())));
        }
        assertEquals(Permission.values().length + 1, authorities.size());
    }

    @Test
    void getAuthoritiesForRole_nullShouldReturnEmptySet() {
        assertTrue(PermissionMapping.getAuthoritiesForRole(null).isEmpty());
    }

    @Test
    void getAuthoritiesForUser_shouldCombineRoleAndExplicitPermissions() {
        User user = new User();
        user.setRoles(Set.of(Role.USER, Role.CREATOR));
        user.setPermissions(Set.of(Permission.USER_DELETE));

        Set<SimpleGrantedAuthority> authorities = PermissionMapping.getAuthoritiesForUser(user);

        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_USER")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority("ROLE_CREATOR")));
        assertTrue(authorities.contains(new SimpleGrantedAuthority(Permission.POST_CREATE.name())));
        assertTrue(authorities.contains(new SimpleGrantedAuthority(Permission.POST_UPDATE.name())));
        assertTrue(authorities.contains(new SimpleGrantedAuthority(Permission.USER_DELETE.name())));
    }
}

