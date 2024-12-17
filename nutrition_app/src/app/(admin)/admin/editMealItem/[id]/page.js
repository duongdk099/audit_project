"use client";
import { useEffect, useState } from "react";
import UpdateMealItem from "@/components/database_components/mealItem/UpdateMealItem";

const UpdateMealItemPage = () => {
  const [mealItemId, setMealItemId] = useState(null);

  useEffect(() => {
    const path = window.location.pathname; // Get the full path (e.g., /meal/update/123)
    const pathParts = path.split("/"); // Split the path by "/"
    const id = pathParts[pathParts.length - 1]; // Get the last part of the path which is the ID
    setMealItemId(id); // Set the mealItemId state with the extracted ID
  }, []);

  if (!mealItemId) {
    return <p>Loading...</p>; // Display a loading state until mealItemId is set
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Update Meal Item</h1>
      {/* Pass mealItemId to UpdateMealItem component */}
      <UpdateMealItem mealItemId={mealItemId} />
    </div>
  );
};

export default UpdateMealItemPage;
