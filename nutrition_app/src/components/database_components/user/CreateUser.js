import { useState } from "react";
import { createUser } from "../../../services/users"; // Import the function from your database file
import bcrypt from "bcryptjs"; // Import bcryptjs for password hashing

const CreateUser = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(""); // State for error message
  const [success, setSuccess] = useState(""); // State for success message

  // Function to validate email format
  const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  // Function to validate password
  const isValidPassword = (password) => {
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return passwordRegex.test(password);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Clear any previous messages
    setError("");
    setSuccess("");

    // Validate email format
    if (!isValidEmail(email)) {
      setError("Invalid email format.");
      return;
    }

    // Validate password strength
    if (!isValidPassword(password)) {
      setError(
        "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character."
      );
      return;
    }
    
    try {
      // Hash the password before passing it to the createUser function
      const hashedPassword = await bcrypt.hash(password, 10);

      // Pass the hashed password instead of the plain text password
      const newUser = await createUser(username, email, hashedPassword);

      // Display success message
      setSuccess("User created successfully!");

      // Clear form inputs
      setUsername("");
      setEmail("");
      setPassword("");
    } catch (error) {
      // Display the error message when email is already in use
      setError(error.message);
    }
  };

  return (
    <div>
      {error && <p style={{ color: 'red' }}>{error}</p>} {/* Display error message */}
      {success && <p style={{ color: 'green' }}>{success}</p>} {/* Display success message */}
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Username"
          value={username || ""} // Ensure value is a string
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <input
          type="email"
          placeholder="Email"
          value={email || ""} // Ensure value is a string
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password || ""} // Ensure value is a string
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button type="submit">Create User</button>
      </form>
    </div>
  );
};

export default CreateUser;