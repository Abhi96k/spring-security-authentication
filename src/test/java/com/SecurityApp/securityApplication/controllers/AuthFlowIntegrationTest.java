package com.SecurityApp.securityApplication.controllers;

import com.SecurityApp.securityApplication.entities.User;
import com.SecurityApp.securityApplication.entities.enums.Role;
import com.SecurityApp.securityApplication.repositories.UserRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final Pattern ACCESS_TOKEN = Pattern.compile("\"accessToken\":\"([^\"]+)\"");

    private String uniqueEmail() {
        return UUID.randomUUID() + "@example.com";
    }

    private MvcResult login(String email, String password) throws Exception {
        return mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("refreshToken"))
                .andReturn();
    }

    private String accessToken(MvcResult result) throws Exception {
        Matcher matcher = ACCESS_TOKEN.matcher(result.getResponse().getContentAsString());
        if (!matcher.find()) {
            throw new AssertionError("No access token in response");
        }
        return matcher.group(1);
    }

    private void createUser(String email, String password, Role role) {
        User user = new User();
        user.setEmail(email);
        user.setName(role.name());
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles(new HashSet<>(Set.of(role)));
        userRepository.save(user);
    }

    @Test
    void uiIsServedWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().isOk());
        mockMvc.perform(get("/index.html")).andExpect(status().isOk());
        mockMvc.perform(get("/js/app.js")).andExpect(status().isOk());
        mockMvc.perform(get("/css/app.css")).andExpect(status().isOk());
    }

    @Test
    void protectedEndpointsReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/posts")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/users/me")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/posts").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signupLoginAndUserPermissions() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Test\",\"email\":\"" + email + "\",\"password\":\"secret\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));

        String token = accessToken(login(email, "secret"));

        mockMvc.perform(get("/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        // USER can view posts ...
        mockMvc.perform(get("/posts").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // ... but cannot create them or reach admin APIs
        mockMvc.perform(post("/posts").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"t\",\"description\":\"d\"}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/admin/users").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void authenticatedRequestDoesNotCreateLoggedInHttpSession() throws Exception {
        String email = uniqueEmail();
        createUser(email, "pw", Role.USER);
        String token = accessToken(login(email, "pw"));

        MvcResult result = mockMvc.perform(get("/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        // Re-using that HTTP session without a token must be anonymous again (so login works after logout)
        org.springframework.mock.web.MockHttpSession session =
                (org.springframework.mock.web.MockHttpSession) result.getRequest().getSession();
        mockMvc.perform(get("/users/me").session(session)).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/auth/login").session(session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"pw\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        String email = uniqueEmail();
        createUser(email, "right", Role.USER);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"wrong\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void creatorCanCreateAndAdminCanDeleteAndManageRoles() throws Exception {
        String creator = uniqueEmail();
        String admin = uniqueEmail();
        createUser(creator, "pw", Role.CREATOR);
        createUser(admin, "pw", Role.ADMIN);

        String creatorToken = accessToken(login(creator, "pw"));
        String created = mockMvc.perform(post("/posts").header("Authorization", "Bearer " + creatorToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Hello\",\"description\":\"World\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Hello"))
                .andReturn().getResponse().getContentAsString();
        String postId = created.replaceAll(".*\"id\":(\\d+).*", "$1");

        // CREATOR lacks POST_DELETE
        mockMvc.perform(delete("/posts/" + postId).header("Authorization", "Bearer " + creatorToken))
                .andExpect(status().isForbidden());

        String adminToken = accessToken(login(admin, "pw"));
        mockMvc.perform(delete("/posts/" + postId).header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/posts/" + postId).header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());

        Long creatorId = userRepository.findByEmail(creator).orElseThrow().getId();
        mockMvc.perform(put("/admin/users/" + creatorId + "/roles").header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"USER\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles[0]").value("USER"));
        mockMvc.perform(get("/admin/users").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }

    @Test
    void refreshRotatesTokenAndLogoutEndsSession() throws Exception {
        String email = uniqueEmail();
        createUser(email, "pw", Role.USER);

        Cookie refreshCookie = login(email, "pw").getResponse().getCookie("refreshToken");
        assertNotNull(refreshCookie);

        // Refresh works without an access token (it has usually expired by then)
        MvcResult refreshed = mockMvc.perform(post("/auth/refresh").cookie(refreshCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();
        Cookie rotated = refreshed.getResponse().getCookie("refreshToken");
        assertNotNull(rotated);
        assertNotEquals(refreshCookie.getValue(), rotated.getValue());

        // The old refresh token no longer works after rotation
        mockMvc.perform(post("/auth/refresh").cookie(refreshCookie))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/auth/logout").cookie(rotated))
                .andExpect(status().isNoContent());
        mockMvc.perform(post("/auth/refresh").cookie(rotated))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/auth/refresh")).andExpect(status().isUnauthorized());
    }
}
