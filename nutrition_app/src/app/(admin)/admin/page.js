"use client";

import React, { useEffect, useState } from "react";
import Cookies from "js-cookie"; // Import js-cookie to manage cookies
import BackOffice from "../../../components/admin_components/BackOffice";

const AdminPage = () => {
  const [isAdmin, setIsAdmin] = useState(false); // State to determine if the user is an admin
  const [loading, setLoading] = useState(true); // Loading state while checking user role

  useEffect(() => {
    const authToken = Cookies.get("authToken"); // Get the authToken from cookies

    if (!authToken) {
      // If no auth token, redirect to home after a delay
      redirectToHomeWithMessage();
    } else {
      try {
        // Parse the auth token to get the user information
        const user = JSON.parse(authToken);

        if (user?.role && user.role.includes("Admin")) {
          // Check if the user has the "Admin" role
          setIsAdmin(true);
        } else {
          // If the user does not have the "Admin" role, redirect to home after a delay
          redirectToHomeWithMessage();
        }
      } catch (error) {
        // Handle parsing errors, if the token is not a valid JSON
        console.error("Invalid auth token, redirecting to home...");
        redirectToHomeWithMessage();
      } finally {
        setLoading(false);
      }
    }
  }, []);

  // Helper function to redirect to home with a delay and a message
  const redirectToHomeWithMessage = () => {
    setTimeout(() => {
      window.location.href = "/";
    }, 3000); // Redirect after 3 seconds
  };

  if (loading) return <div>Loading...</div>; // Show loading while authentication is being verified

  if (!isAdmin) {
    // Show a message while waiting for the redirect
    return (
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold text-center mb-4">
          You can&apos;t know about this page, redirecting to the home page...
        </h1>
      </div>
    );
  }

  // Render the admin back office if the user is authenticated as an Admin
  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-4">Admin Back Office</h1>
      <BackOffice />
    </div>
  );
};

export default AdminPage;
