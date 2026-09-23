# Spring Security Authentication

Spring Boot app with JWT login, refresh-token sessions, GitHub OAuth2 login, role/permission-based authorization and a small web UI.

## Run

**Quick start (no database needed)** – uses in-memory H2 and seeds demo accounts:

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

Open http://localhost:8080 and log in with one of:

| Email | Password | Role |
|---|---|---|
| admin@example.com | admin123 | ADMIN (all permissions, user management) |
| creator@example.com | creator123 | CREATOR (view + create posts) |
| user@example.com | user123 | USER (view posts) |

**With MySQL** (default profile): start MySQL on `localhost:3306`, then `./mvnw spring-boot:run`.
Connection settings can be overridden with `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`.

GitHub login needs an OAuth app whose callback URL is `http://localhost:8080/login/oauth2/code/github`
(override credentials with `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`).

## Tests

```bash
./mvnw test
```

## API

| Method | Path | Access |
|---|---|---|
| POST | `/auth/signup` | anonymous |
| POST | `/auth/login` | anonymous – returns access token, sets `refreshToken` HttpOnly cookie |
| POST | `/auth/refresh` | refresh cookie – rotates the refresh token |
| POST | `/auth/logout` | ends the refresh-token session |
| GET | `/users/me` | authenticated |
| GET | `/posts`, `/posts/{id}` | `POST_VIEW` |
| POST | `/posts` | `POST_CREATE` |
| DELETE | `/posts/{id}` | `POST_DELETE` |
| GET | `/admin/users` | `ROLE_ADMIN` |
| PUT | `/admin/users/{id}/roles` | `ROLE_ADMIN` – body `{"roles":["CREATOR"]}` |

Send the access token as `Authorization: Bearer <token>`.
