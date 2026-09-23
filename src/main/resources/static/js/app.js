(() => {
    "use strict";

    const TOKEN_KEY = "accessToken";
    const $ = (id) => document.getElementById(id);

    // ---------- token storage ----------
    let accessToken = null;
    function loadToken() {
        try { accessToken = localStorage.getItem(TOKEN_KEY); } catch (e) { accessToken = null; }
    }
    function saveToken(token) {
        accessToken = token;
        try {
            if (token) localStorage.setItem(TOKEN_KEY, token);
            else localStorage.removeItem(TOKEN_KEY);
        } catch (e) { /* storage unavailable: keep in memory only */ }
    }

    function decodeJwt(token) {
        try {
            const part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
            const json = decodeURIComponent(atob(part).split("").map(c =>
                "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join(""));
            return JSON.parse(json);
        } catch (e) {
            return null;
        }
    }
    const claims = () => (accessToken ? decodeJwt(accessToken) : null) || {};
    const hasAuthority = (a) => (claims().roles || []).includes(a);

    // ---------- API ----------
    async function readError(res) {
        const text = await res.text();
        try {
            const body = JSON.parse(text);
            return body.error || body.message || text;
        } catch (e) {
            return text || res.status + " " + res.statusText;
        }
    }

    let refreshing = null;
    // Uses the HttpOnly refresh cookie; no Authorization header so an expired token can't block it.
    function refreshAccessToken() {
        if (!refreshing) {
            refreshing = fetch("/auth/refresh", { method: "POST", credentials: "same-origin" })
                .then(async res => {
                    if (!res.ok) throw new Error(await readError(res));
                    const body = await res.json();
                    saveToken(body.accessToken);
                    return body.accessToken;
                })
                .finally(() => { refreshing = null; });
        }
        return refreshing;
    }

    async function api(path, options = {}, retry = true) {
        const headers = Object.assign({}, options.headers);
        if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
        if (accessToken) headers["Authorization"] = "Bearer " + accessToken;

        const res = await fetch(path, Object.assign({}, options, { headers, credentials: "same-origin" }));

        if (res.status === 401 && retry) {
            try {
                await refreshAccessToken();
            } catch (e) {
                signOutLocally("Your session expired, please log in again.");
                throw new Error("Session expired");
            }
            renderToken();
            return api(path, options, false);
        }
        if (!res.ok) {
            const message = await readError(res);
            throw new Error(res.status === 403 ? "Access denied: " + message : message);
        }
        if (res.status === 204) return null;
        const text = await res.text();
        return text ? JSON.parse(text) : null;
    }

    // Unauthenticated calls (login/signup must be anonymous: @PreAuthorize("isAnonymous()"))
    async function publicPost(path, data) {
        const res = await fetch(path, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
        if (!res.ok) throw new Error(await readError(res));
        return res.json();
    }

    // ---------- UI helpers ----------
    let toastTimer;
    function toast(message, isError = false) {
        const el = $("toast");
        el.textContent = message;
        el.classList.toggle("error", isError);
        el.classList.remove("hidden");
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
    }
    function chips(container, values) {
        container.replaceChildren(...values.map(v => {
            const span = document.createElement("span");
            span.className = "chip";
            span.textContent = v;
            return span;
        }));
    }
    async function withBusy(button, fn) {
        button.disabled = true;
        try { await fn(); } catch (e) { toast(e.message, true); } finally { button.disabled = false; }
    }

    // ---------- views ----------
    function showAuth() {
        $("appView").classList.add("hidden");
        $("userBadge").classList.add("hidden");
        $("authView").classList.remove("hidden");
    }

    async function showApp() {
        $("authView").classList.add("hidden");
        $("appView").classList.remove("hidden");
        $("userBadge").classList.remove("hidden");
        renderToken();
        try {
            await loadProfile();
        } catch (e) {
            if (accessToken) toast(e.message, true);
            return;
        }
        loadPosts();
        if (hasAuthority("ROLE_ADMIN")) loadUsers();
    }

    function signOutLocally(message) {
        saveToken(null);
        showAuth();
        if (message) toast(message, true);
    }

    let expiryTimer;
    function renderToken() {
        const c = claims();
        $("tokenRaw").textContent = accessToken || "";
        const display = Object.assign({}, c);
        if (c.iat) display.iat = c.iat + " (" + new Date(c.iat * 1000).toLocaleString() + ")";
        if (c.exp) display.exp = c.exp + " (" + new Date(c.exp * 1000).toLocaleString() + ")";
        $("tokenClaims").textContent = JSON.stringify(display, null, 2);

        const roleAuthorities = c.roles || [];
        const canCreate = roleAuthorities.includes("POST_CREATE");
        $("postForm").classList.toggle("hidden", !canCreate);
        $("postCreateHint").classList.toggle("hidden", canCreate);
        $("adminCard").classList.toggle("hidden", !roleAuthorities.includes("ROLE_ADMIN"));

        clearInterval(expiryTimer);
        const tick = () => {
            if (!c.exp) { $("tokenExpiry").textContent = "–"; return; }
            const secs = Math.round(c.exp - Date.now() / 1000);
            $("tokenExpiry").textContent = secs <= 0 ? "expired"
                : Math.floor(secs / 60) + "m " + String(secs % 60).padStart(2, "0") + "s";
        };
        tick();
        expiryTimer = setInterval(tick, 1000);
    }

    async function loadProfile() {
        const me = await api("/users/me");
        $("profileName").textContent = me.name;
        $("profileEmail").textContent = me.email;
        $("profileId").textContent = me.id;
        chips($("profileRoles"), me.roles);
        chips($("profileAuthorities"), (claims().roles || []).filter(a => !a.startsWith("ROLE_")));
        $("userBadgeName").textContent = me.name;
    }

    async function loadPosts() {
        const list = $("postList");
        try {
            const posts = await api("/posts");
            const canDelete = hasAuthority("POST_DELETE");
            if (!posts.length) {
                const li = document.createElement("li");
                li.className = "empty";
                li.textContent = "No posts yet.";
                list.replaceChildren(li);
                return;
            }
            list.replaceChildren(...posts.map(post => {
                const li = document.createElement("li");
                const body = document.createElement("div");
                const title = document.createElement("div");
                title.className = "post-title";
                title.textContent = "#" + post.id + " · " + (post.title || "(untitled)");
                const desc = document.createElement("div");
                desc.className = "post-body";
                desc.textContent = post.description || "";
                body.append(title, desc);
                li.append(body);
                if (canDelete) {
                    const del = document.createElement("button");
                    del.className = "btn btn-danger";
                    del.textContent = "Delete";
                    del.addEventListener("click", () => withBusy(del, async () => {
                        await api("/posts/" + post.id, { method: "DELETE" });
                        toast("Post deleted");
                        loadPosts();
                    }));
                    li.append(del);
                }
                return li;
            }));
        } catch (e) {
            const li = document.createElement("li");
            li.className = "empty";
            li.textContent = e.message;
            list.replaceChildren(li);
        }
    }

    const ROLES = ["USER", "CREATOR", "ADMIN"];
    async function loadUsers() {
        const tbody = $("userTable");
        try {
            const users = await api("/admin/users");
            const myId = claims().userId;
            tbody.replaceChildren(...users.map(u => {
                const tr = document.createElement("tr");
                [u.id, u.name, u.email].forEach(v => {
                    const td = document.createElement("td");
                    td.textContent = v;
                    tr.append(td);
                });
                const td = document.createElement("td");
                const select = document.createElement("select");
                ROLES.forEach(r => select.add(new Option(r, r, false, (u.roles || []).includes(r))));
                // Highest role wins when a user has several
                select.value = ROLES.slice().reverse().find(r => (u.roles || []).includes(r)) || "USER";
                select.disabled = u.id === myId;
                select.title = u.id === myId ? "You can't change your own role" : "";
                select.addEventListener("change", () => withBusy(select, async () => {
                    await api("/admin/users/" + u.id + "/roles", {
                        method: "PUT",
                        body: JSON.stringify({ roles: [select.value] })
                    });
                    toast(u.email + " is now " + select.value);
                }));
                td.append(select);
                tr.append(td);
                return tr;
            }));
        } catch (e) {
            toast(e.message, true);
        }
    }

    // ---------- events ----------
    document.querySelectorAll(".tab").forEach(tab => tab.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t === tab));
        $("loginForm").classList.toggle("hidden", tab.dataset.tab !== "login");
        $("signupForm").classList.toggle("hidden", tab.dataset.tab !== "signup");
    }));

    document.querySelectorAll(".fill-demo").forEach(btn => btn.addEventListener("click", () => {
        const form = $("loginForm");
        form.email.value = btn.dataset.email;
        form.password.value = btn.dataset.password;
        document.querySelector('.tab[data-tab="login"]').click();
    }));

    $("loginForm").addEventListener("submit", (e) => {
        e.preventDefault();
        const form = e.target;
        withBusy(form.querySelector("button"), async () => {
            const body = await publicPost("/auth/login", { email: form.email.value, password: form.password.value });
            saveToken(body.accessToken);
            form.reset();
            toast("Logged in");
            await showApp();
        });
    });

    $("signupForm").addEventListener("submit", (e) => {
        e.preventDefault();
        const form = e.target;
        withBusy(form.querySelector("button"), async () => {
            const data = { name: form.name.value, email: form.email.value, password: form.password.value };
            await publicPost("/auth/signup", data);
            const body = await publicPost("/auth/login", { email: data.email, password: data.password });
            saveToken(body.accessToken);
            form.reset();
            toast("Account created");
            await showApp();
        });
    });

    $("logoutBtn").addEventListener("click", () => withBusy($("logoutBtn"), async () => {
        await fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
        signOutLocally();
        toast("Logged out");
    }));

    $("refreshBtn").addEventListener("click", () => withBusy($("refreshBtn"), async () => {
        try {
            await refreshAccessToken();
        } catch (e) {
            signOutLocally("Refresh failed: " + e.message);
            return;
        }
        renderToken();
        await loadProfile();
        toast("Token refreshed");
    }));

    $("reloadPostsBtn").addEventListener("click", loadPosts);
    $("reloadUsersBtn").addEventListener("click", loadUsers);

    $("postForm").addEventListener("submit", (e) => {
        e.preventDefault();
        const form = e.target;
        withBusy(form.querySelector("button"), async () => {
            await api("/posts", {
                method: "POST",
                body: JSON.stringify({ title: form.title.value, description: form.description.value })
            });
            form.reset();
            toast("Post created");
            loadPosts();
        });
    });

    // ---------- boot ----------
    loadToken();

    // GitHub login redirects back with the token in the URL fragment: /#token=...
    const hash = new URLSearchParams(location.hash.slice(1));
    if (hash.get("token")) {
        saveToken(hash.get("token"));
        history.replaceState(null, "", location.pathname);
        toast("Logged in with GitHub");
    }
    const query = new URLSearchParams(location.search);
    if (query.get("error")) {
        history.replaceState(null, "", location.pathname);
        toast("GitHub login failed", true);
    }

    if (accessToken) showApp(); else showAuth();
})();
