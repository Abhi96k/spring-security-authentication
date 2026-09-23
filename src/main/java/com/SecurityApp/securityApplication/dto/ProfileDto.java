package com.SecurityApp.securityApplication.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProfileDto {
    private Long id;
    private String email;
    private String name;
    private List<String> roles;
    private List<String> authorities;
}
