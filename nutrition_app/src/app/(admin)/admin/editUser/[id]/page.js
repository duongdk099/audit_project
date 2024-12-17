"use client";
import { useEffect, useState } from "react";
import EditUser from "@/components/database_components/user/EditUser";

const EditUserPage = () => {
  const [userId, setUserId] = useState(null);

  // Extract the userId from the URL path manually
  useEffect(() => {
    const path = window.location.pathname; // Get the full path (e.g., /admin/editUser/2)
    const pathParts = path.split("/"); // Split the path by "/" to get the parts
    const id = pathParts[pathParts.length - 1]; // The last part of the URL is the user ID

    if (id) {
      setUserId(id); // Set the userId state if it's found in the path
    }
  }, []);

  if (!userId) {
    return <p>Loading...</p>; // Show a loading message while waiting for the ID
  }

  return (
    <div>
      {/* Pass the userId to the EditUser component */}
      <EditUser userId={userId} />
    </div>
  );
};

export default EditUserPage;
