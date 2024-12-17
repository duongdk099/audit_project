"use client";
import { useEffect, useState } from "react";
import UpdateMeal from "@/components/database_components/meals/UpdateMeal";
const UpdateMealPage = () => {
  const [mealId, setMealId] = useState(null);

  useEffect(() => {
    const path = window.location.pathname; // Get the full path (e.g., /meal/update/123)
    const pathParts = path.split("/"); // Split the path by "/"
    const id = pathParts[pathParts.length - 1]; // Get the last part of the path which is the ID
    setMealId(id); // Set the mealId state with the extracted ID
  }, []);

  if (!mealId) {
    return <p>Loading...</p>; // Display a loading state until mealId is set
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Update Meal</h1>
      {/* Pass mealId to UpdateMeal component */}
      <UpdateMeal mealId={mealId} />
    </div>
  );
};

export default UpdateMealPage;
