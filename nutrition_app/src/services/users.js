"use server";
import bcrypt from "bcryptjs";
import { neon } from "@neondatabase/serverless";
import { createUserRole } from "./user_roles";
export async function getData() {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
  const data = await sql`SELECT * FROM users`;
  return data;
}

export async function getUsers() {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
  const users = await sql`SELECT * FROM users`;
  return users;
}

// Get a user by their user ID
export async function getUserById(userId) {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);

  const user = await sql`
    SELECT * FROM users WHERE user_id = ${userId};
  `;

  if (user.length === 0) {
    throw new Error("User not found");
  }

  return user[0]; // Return the user object
}
export async function createUser({username, email, password}) {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);

  try {
    // Check if any input is undefined
    if (!username || !email || !password) {
      throw new Error("All fields (username, email, password) are required.");
    }

    // Check if the email already exists in the database
    const existingUser = await sql`
        SELECT * FROM users
        WHERE email = ${email}
      `;

    if (existingUser.length > 0) {
      throw new Error("Email is already in use.");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database if email is unique
    const newUser = await sql`
        INSERT INTO users (username, email, password_hash)
        VALUES (${username}, ${email}, ${hashedPassword})
        RETURNING *;
      `;

    // Get the newly created user ID
    const userId = newUser[0].user_id;

    // Assign default role (role_id = 1) to the new user
    await createUserRole(userId, 1);

    return newUser;
  } catch (error) {
    console.error("Error in createUser:", error.message); // Log detailed error
    throw error;
  }
}


export async function updateUser(userId, updatedData) {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
  const { username, email, password } = updatedData;

  // Hash the password if it's provided
  let hashedPassword = null;
  if (password) {
    hashedPassword = await bcrypt.hash(password, 10);
  }

  // If password is provided, update all fields including password
  if (hashedPassword) {
    const updatedUser = await sql`
      UPDATE users
      SET username = ${username}, 
          email = ${email}, 
          password_hash = ${hashedPassword}
      WHERE user_id = ${userId}
      RETURNING *;
    `;
    return updatedUser;
  } else {
    // If password is not provided, update only username and email
    const updatedUser = await sql`
      UPDATE users
      SET username = ${username}, 
          email = ${email}
      WHERE user_id = ${userId}
      RETURNING *;
    `;
    return updatedUser;
  }
}

export async function login(email, password) {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);

  // Find the user with the given email
  const user = await sql`
      SELECT * FROM users WHERE email = ${email}
    `;

  if (user.length === 0) {
    // If no user is found, return an error or empty result
    throw new Error("User not found.");
  }

  const hashedPassword = user[0].password_hash;

  // Compare the plain password with the hashed password in the database
  const isPasswordValid = await bcrypt.compare(password, hashedPassword);

  if (!isPasswordValid) {
    throw new Error("Invalid password.");
  }

  // If the password is valid, return the user details
  return user[0];
}

export async function updatePassword(userId, newPassword) {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
  const updatedUser = await sql`
        UPDATE users
        SET password_hash = ${newPassword}
        WHERE user_id = ${userId}
        RETURNING *;
    `;
  return updatedUser;
}

export async function deleteUser(userId) {
  const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
  const deletedUser = await sql`
        DELETE FROM users
        WHERE user_id = ${userId}
        RETURNING *;
    `;
  return deletedUser;
}
