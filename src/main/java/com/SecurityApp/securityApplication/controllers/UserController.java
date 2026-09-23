package com.SecurityApp.securityApplication.controllers;

import com.SecurityApp.securityApplication.dto.ProfileDto;
import com.SecurityApp.securityApplication.entities.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/users")
public class UserController {

    // Profile of the caller, built from the JWT-authenticated principal
    @GetMapping("/me")
    public ProfileDto me(@AuthenticationPrincipal User user) {
        return toProfile(user);
    }

    static ProfileDto toProfile(User user) {
        return new ProfileDto(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getRoles() == null ? java.util.List.of()
                        : user.getRoles().stream().map(Enum::name).sorted().toList(),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()
        );
    }
}
