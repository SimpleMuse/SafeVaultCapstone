import { getAuthorizedResponse } from "./Home.razor.js";

export async function getAccounts() {
    const response = await getAuthorizedResponse("/account/admin/accounts");
    if (!response?.ok) {
        throw new Error(`Account list request failed (${response?.status ?? 401}).`);
    }

    return response.json();
}

export async function updateRole(userId, role) {
    const response = await getAuthorizedResponse("/account/admin/role", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, role })
    });
    if (!response?.ok) {
        throw new Error(`Role update request failed (${response?.status ?? 401}).`);
    }
}
