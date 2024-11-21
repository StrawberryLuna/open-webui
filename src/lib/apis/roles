import { WEBUI_API_BASE_URL } from '$lib/constants';

// Fetch all roles
export const getRoles = async (token: string) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        }
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Fetch a role by name
export const getRoleByName = async (token: string, roleName: string) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/${roleName}`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        }
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Fetch roles by tier
export const getRolesByTier = async (token: string, tier: string) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/tier/${tier}`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        }
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Create a new role
export const createRole = async (token: string, body: object) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/create`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(body)
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Update a role
export const updateRole = async (token: string, roleName: string, body: object) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/${roleName}/update`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(body)
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Update role tier
export const updateRoleTier = async (token: string, roleName: string, body: object) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/${roleName}/tier`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(body)
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Bulk update tiers
export const bulkUpdateTiers = async (token: string, body: object) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/bulk-update-tiers`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(body)
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Delete a role
export const deleteRole = async (token: string, roleName: string) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/${roleName}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        }
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};

// Fetch available tiers
export const getAvailableTiers = async (token: string) => {
    let error = null;

    const res = await fetch(`${WEBUI_API_BASE_URL}/roles/system/available-tiers`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
        }
    })
        .then(async (res) => {
            if (!res.ok) throw await res.json();
            return res.json();
        })
        .catch((err) => {
            console.log(err);
            error = err.detail;
            return null;
        });

    if (error) throw error;
    return res;
};
