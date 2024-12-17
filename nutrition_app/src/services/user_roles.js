// user_roles.js

import { neon } from '@neondatabase/serverless';

// Create a new user role assignment (assign a role to a user)
export async function createUserRole(userId, roleId) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);

    // Check if the user already has the role
    const existingRoles = await sql`
        SELECT role_id FROM user_roles 
        WHERE user_id = ${userId} AND role_id = ${roleId};
    `;

    if (existingRoles.length > 0) {
        return { message: 'User already has this role' };
    }

    
    const newUserRole = await sql`
        INSERT INTO user_roles (user_id, role_id)
        VALUES (${userId}, ${roleId})
        RETURNING *;
    `;
    return newUserRole;
}

// Get roles assigned to a specific user
export async function getRolesByUserId(userId) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const userRoles = await sql`
        SELECT r.role_name
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = ${userId};
    `;
    return userRoles[0].role_name;
}

// Get users assigned to a specific role
export async function getUsersByRoleId(roleId) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const users = await sql`
        SELECT u.user_id, u.username, u.email
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.user_id
        WHERE ur.role_id = ${roleId};
    `;
    return users;
}

// Delete a specific role from a user (unassign role from a user)
export async function deleteUserRole(userId, roleId) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const deletedUserRole = await sql`
        DELETE FROM user_roles
        WHERE user_id = ${userId} AND role_id = ${roleId}
        RETURNING *;
    `;
    return deletedUserRole;
}

// Get all roles available in the system
export async function getAllRoles() {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const roles = await sql`SELECT * FROM roles;`;
    return roles;
}

// Create a new role (e.g., User, VIP, Admin)
export async function createRole(roleName) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const newRole = await sql`
        INSERT INTO roles (role_name)
        VALUES (${roleName})
        RETURNING *;
    `;
    return newRole;
}
