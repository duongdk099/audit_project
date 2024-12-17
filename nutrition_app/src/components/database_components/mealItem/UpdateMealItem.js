"use client";
import { useState, useEffect } from "react";
import { updateMealItem, getMealItemById } from "@/services/meal_items"; // Import necessary functions

const UpdateMealItem = ({ mealItemId }) => {
  const [foodName, setFoodName] = useState("");
  const [foodQuantity, setFoodQuantity] = useState("");
  const [foodCalories, setFoodCalories] = useState("");
  const [foodProtein, setFoodProtein] = useState("");
  const [foodCarb, setFoodCarb] = useState("");
  const [foodFiber, setFoodFiber] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Fetch current meal item data and pre-fill form
  useEffect(() => {
    const fetchMealItem = async () => {
      try {
        const mealItem = await getMealItemById(mealItemId); // Fetch the meal item by ID
        setFoodName(mealItem.food_name);
        setFoodQuantity(mealItem.food_quantity);
        setFoodCalories(mealItem.food_calories);
        setFoodProtein(mealItem.food_protein);
        setFoodCarb(mealItem.food_carb);
        setFoodFiber(mealItem.food_fiber);
      } catch (err) {
        setError("Error fetching meal item data");
      }
    };

    if (mealItemId) {
      fetchMealItem();
    }
  }, [mealItemId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const updatedData = {
      foodName,
      foodQuantity,
      foodCalories,
      foodProtein,
      foodCarb,
      foodFiber,
    };

    try {
      const updatedMealItem = await updateMealItem(mealItemId, updatedData);
      setSuccess("Meal item updated successfully!");
    } catch (error) {
      setError(error.message);
    }
  };

  return (
    <div className="max-w-lg mx-auto bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold text-center mb-6">Update Meal Item</h2>
      {error && <p className="text-red-500 text-center mb-4">{error}</p>}
      {success && <p className="text-green-500 text-center mb-4">{success}</p>}
      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="flex flex-col">
          <label htmlFor="mealItemId" className="mb-2 text-gray-700">Meal Item ID</label>
          <input
            type="text"
            id="mealItemId"
            value={mealItemId}
            readOnly
            className="p-2 border border-gray-300 rounded-md bg-gray-200 cursor-not-allowed"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="foodName" className="mb-2 text-gray-700">Food Name</label>
          <input
            type="text"
            id="foodName"
            placeholder="Food Name"
            value={foodName}
            onChange={(e) => setFoodName(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="foodQuantity" className="mb-2 text-gray-700">Quantity</label>
          <input
            type="number"
            id="foodQuantity"
            placeholder="Quantity"
            value={foodQuantity}
            onChange={(e) => setFoodQuantity(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="foodCalories" className="mb-2 text-gray-700">Calories</label>
          <input
            type="number"
            id="foodCalories"
            placeholder="Calories"
            value={foodCalories}
            onChange={(e) => setFoodCalories(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="foodProtein" className="mb-2 text-gray-700">Protein</label>
          <input
            type="number"
            id="foodProtein"
            placeholder="Protein"
            value={foodProtein}
            onChange={(e) => setFoodProtein(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="foodCarb" className="mb-2 text-gray-700">Carbs</label>
          <input
            type="number"
            id="foodCarb"
            placeholder="Carbs"
            value={foodCarb}
            onChange={(e) => setFoodCarb(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="foodFiber" className="mb-2 text-gray-700">Fiber</label>
          <input
            type="number"
            id="foodFiber"
            placeholder="Fiber"
            value={foodFiber}
            onChange={(e) => setFoodFiber(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-blue-500 text-white py-2 rounded-md hover:bg-blue-600 transition duration-300"
        >
          Update Meal Item
        </button>
      </form>
    </div>
  );
};

export default UpdateMealItem;