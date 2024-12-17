export const registerUser = async (userData) => {
  const users = JSON.parse(localStorage.getItem("users")) || [];

  // Check if the user already exists
  const existingUser = users.find(
    (user) => user.username === userData.username
  );
  if (existingUser) {
    throw new Error("User already exists");
  }

  // Add new user
  users.push(userData);
  localStorage.setItem("users", JSON.stringify(users));

  return true; // Return success
};
