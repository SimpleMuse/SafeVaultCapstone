const accessTokenKey = "safevault.accessToken";

function antiForgeryToken() {
    return document.querySelector('input[name="__RequestVerificationToken"]')?.value ?? "";
}

async function refreshAccessToken() {
    const response = await fetch("/account/refresh", {
        method: "POST",
        credentials: "same-origin",
        headers: { "RequestVerificationToken": antiForgeryToken() }
    });

    if (response.status === 204) {
        sessionStorage.removeItem(accessTokenKey);
        return null;
    }

    if (!response.ok) {
        if (response.status === 401) {
            sessionStorage.removeItem(accessTokenKey);
            return null;
        }

        throw new Error(`Token refresh failed (${response.status}).`);
    }

    const tokens = await response.json();
    sessionStorage.setItem(accessTokenKey, tokens.accessToken);
    return tokens.accessToken;
}

export async function getAuthorizedResponse(url, options = {}) {
    let accessToken = sessionStorage.getItem(accessTokenKey) ?? await refreshAccessToken();
    if (!accessToken) {
        return null;
    }

    let response = await fetch(url, {
        ...options,
        headers: { ...options.headers, Authorization: `Bearer ${accessToken}` }
    });

    if (response.status === 401) {
        accessToken = await refreshAccessToken();
        if (!accessToken) {
            return null;
        }

        response = await fetch(url, {
            ...options,
            headers: { ...options.headers, Authorization: `Bearer ${accessToken}` }
        });
    }

    return response;
}

export async function getCurrentSession() {
    const response = await getAuthorizedResponse("/account/me");
    if (!response?.ok) {
        return null;
    }

    return response.json();
}

export async function login(username, password) {
    const response = await fetch("/account/login", {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json",
            "RequestVerificationToken": antiForgeryToken()
        },
        body: JSON.stringify({ username, password })
    });

    if (response.status === 401) {
        return null;
    }

    if (!response.ok) {
        throw new Error(`Sign-in request failed (${response.status}).`);
    }

    const session = await response.json();
    sessionStorage.setItem(accessTokenKey, session.accessToken);
    return { username: session.username, role: session.role };
}

export async function logout() {
    const response = await fetch("/account/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "RequestVerificationToken": antiForgeryToken() }
    });
    if (!response.ok) {
        throw new Error(`Sign-out request failed (${response.status}).`);
    }

    sessionStorage.removeItem(accessTokenKey);
}
