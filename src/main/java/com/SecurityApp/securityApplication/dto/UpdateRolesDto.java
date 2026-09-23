package com.SecurityApp.securityApplication.dto;

import com.SecurityApp.securityApplication.entities.enums.Role;
import lombok.Data;

import java.util.Set;

@Data
public class UpdateRolesDto {
    private Set<Role> roles;
}
