import { useState } from 'react';
import { updatePassword } from '@/services/users'; // Import the function to update the password

const UpdatePassword = () => {
  const [userId, setUserId] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const updatedUser = await updatePassword(userId, newPassword);
      setUserId(''); // Clear form inputs
      setNewPassword('');
    } catch (error) {
      console.error('Error updating password:', error);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="User ID"
        value={userId}
        onChange={(e) => setUserId(e.target.value)}
      />
      <input
        type="password"
        placeholder="New Password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
      />
      <button type="submit">Update Password</button>
    </form>
  );
};

export default UpdatePassword;