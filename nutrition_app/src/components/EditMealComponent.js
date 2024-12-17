// EditMealComponent.js
"use client";
import React from "react";
import EditMealItemLogic from "./EditMealItemLogic"; // Import the logic component

export default function EditMealComponent({ mealItemId }) {
  // The only responsibility of this component is to pass the mealItemId to the logic component
  return (
    <div>
      {/* Pass mealItemId to the EditMealItemLogic component */}
      <EditMealItemLogic mealItemId={mealItemId} />
    </div>
  );
}
