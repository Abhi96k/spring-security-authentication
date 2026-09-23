package com.SecurityApp.securityApplication.services;

import com.SecurityApp.securityApplication.dto.SignUpDto;
import com.SecurityApp.securityApplication.dto.UserDto;
import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.entities.enums.Role;
import com.SecurityApp.securityApplication.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;

    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @PreAuthorize("hasAnyRole('ADMIN') or #userId == authentication.principal.id")
    public @NonNull User getUserById(@NonNull Long userId){
        return userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id " + userId));
    }

    // Internal lookup without method security, used by the JWT filter and the refresh flow
    // where no authenticated principal exists yet.
    public @NonNull User findUserById(@NonNull Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id " + userId));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public @NonNull List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @PreAuthorize("hasRole('ADMIN')")
    public @NonNull User updateRoles(@NonNull Long userId, @NonNull Set<Role> roles) {
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("At least one role is required");
        }
        User user = findUserById(userId);
        user.setRoles(new HashSet<>(roles));
        return userRepository.save(user);
    }

    @PreAuthorize("isAnonymous()")
    public @NonNull UserDto signUp(@NonNull SignUpDto signUpDto) {
        if (signUpDto.getEmail() == null || signUpDto.getEmail().isBlank()
                || signUpDto.getPassword() == null || signUpDto.getPassword().isBlank()) {
            throw new IllegalArgumentException("Email and password are required");
        }
        if (signUpDto.getName() == null || signUpDto.getName().isBlank()) {
            signUpDto.setName(signUpDto.getEmail());
        }
        Optional<User> user = userRepository.findByEmail(signUpDto.getEmail());
        if (user.isPresent()) {
            throw new BadCredentialsException("User already exists " + signUpDto.getEmail());
        }

        User toBeCreated = modelMapper.map(signUpDto, User.class);
        toBeCreated.setPassword(passwordEncoder.encode(signUpDto.getPassword()));
        toBeCreated.setRoles(defaultRoles());

        User savedUser = userRepository.save(toBeCreated);
        return modelMapper.map(savedUser, UserDto.class);
    }

    public @NonNull User getOrCreateOAuthUser(@NonNull String email, @Nullable String name) {
        return userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User user = new User();
                    user.setEmail(email);
                    user.setName(name != null ? name : email);
                    user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
                    user.setRoles(defaultRoles());
                    return userRepository.save(user);
                });
    }

    private Set<Role> defaultRoles() {
        return new HashSet<>(Set.of(Role.USER));
    }

}