package com.SecurityApp.securityApplication.controllers;

import com.SecurityApp.securityApplication.dto.ProfileDto;
import com.SecurityApp.securityApplication.dto.UpdateRolesDto;
import com.SecurityApp.securityApplication.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(path = "/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;

    @GetMapping("/users")
    public List<ProfileDto> getAllUsers() {
        return userService.getAllUsers().stream().map(UserController::toProfile).toList();
    }

    // Role changes apply to tokens issued afterwards (the user has to refresh or log in again)
    @PutMapping("/users/{userId}/roles")
    public ProfileDto updateRoles(@PathVariable Long userId, @RequestBody UpdateRolesDto updateRolesDto) {
        if (updateRolesDto.getRoles() == null) {
            throw new IllegalArgumentException("roles is required");
        }
        return UserController.toProfile(userService.updateRoles(userId, updateRolesDto.getRoles()));
    }
}
