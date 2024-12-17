import { useState, useEffect } from "react";
import { updateUser, getUserById } from "../../../services/users"; // Import your functions

const EditUser = ({ userId }) => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState(""); // Optional password update
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(true);

  // Fetch user data for the userId
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const user = await getUserById(userId); // Fetch user by ID
        setUsername(user.username);
        setEmail(user.email);
      } catch (error) {
        setError(error.message);
      } finally {
        setLoading(false);
      }
    };
    fetchUserData();
  }, [userId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const updatedData = {
        username,
        email,
        ...(password && { password }), // Only add password if it's provided
      };

      await updateUser(userId, updatedData);
      setSuccess("User updated successfully!");
    } catch (error) {
      setError(error.message);
    }
  };

  if (loading)
    return <p className="text-center text-gray-600">Loading user data...</p>;

  return (
    <div className="max-w-md mx-auto p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-semibold text-center text-gray-800 mb-6">
        Edit User
      </h2>
      {error && <p className="text-red-500 text-center mb-4">{error}</p>}
      {success && <p className="text-green-500 text-center mb-4">{success}</p>}
      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="flex flex-col">
          <label htmlFor="userId" className="mb-1 text-gray-700 font-medium">
            User ID
          </label>
          <input
            type="text"
            id="userId"
            value={userId}
            readOnly
            className="p-2 border border-gray-300 rounded-lg bg-gray-200 cursor-not-allowed"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="username" className="mb-1 text-gray-700 font-medium">
            Username
          </label>
          <input
            type="text"
            id="username"
            placeholder="Enter username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="email" className="mb-1 text-gray-700 font-medium">
            Email
          </label>
          <input
            type="email"
            id="email"
            placeholder="Enter email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="password" className="mb-1 text-gray-700 font-medium">
            New Password (optional)
          </label>
          <input
            type="password"
            id="password"
            placeholder="Enter new password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="p-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-blue-500 text-white py-2 rounded-lg hover:bg-blue-600 transition duration-300"
        >
          Update User
        </button>
      </form>
    </div>
  );
};

export default EditUser;
