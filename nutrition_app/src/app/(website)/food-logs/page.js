"use client";
import { useState, useEffect } from "react";
import SearchFood from "@/components/SearchFood";
import FoodDetails from "@/components/FoodDetails";
import { selectFoodItem } from "@/app/api/nutritionixApi"; // Import the API helper
import Cookies from "js-cookie"; // Import js-cookie to manage cookies
import { createMeal } from "@/services/meals"; // Import meal services
import { createMealItem } from "@/services/meal_items"; // Import meal item services

const FoodLogs = () => {
  const [selectedFood, setSelectedFood] = useState(null);
  const [foodLogs, setFoodLogs] = useState([]);
  const [loading, setLoading] = useState(true); // State for loading
  const [userId, setUserId] = useState(null); // Track user ID (from cookies or auth)

  const NUTRITIONIX_API_APP_ID = process.env.NEXT_PUBLIC_NUTRITIONIX_API_APP_ID;
  const NUTRITIONIX_API_APP_KEY =
    process.env.NEXT_PUBLIC_NUTRITIONIX_API_APP_KEY;

  useEffect(() => {
    const authToken = Cookies.get("authToken"); // Check if authToken exists
    if (!authToken || authToken === "") {
      // If no auth token is found, redirect to login page
      window.location.href = "/login";
    } else {
      try {
        const user = JSON.parse(authToken);
        const userId = user?.user_id;
        setUserId(userId); // Assume userId is stored in cookies
      } catch (e) {
        // If parsing fails, redirect to login
        console.error("Invalid auth token, redirecting to login...");
        window.location.href = "/login";
      } finally {
        setLoading(false); // Stop loading once auth process is completed
      }
    }
  }, []);

  const handleSelectFood = async (food) => {
    const nutritionalFood = await selectFoodItem(
      food.name,
      NUTRITIONIX_API_APP_ID,
      NUTRITIONIX_API_APP_KEY
    );
    if (nutritionalFood) {
      setSelectedFood(nutritionalFood);
    }
  };

  const handleAddFood = async (food) => {
    if (!food) {
      setError("No food selected to add.");
      return;
    }

    try {
      // Extract food details from selectedFood state
      const {
        food_name,
        quantity,
        nf_calories,
        nf_protein,
        nf_dietary_fiber,
        nf_total_carbohydrate,
        mealNumber, // Pass meal number from FoodDetails
        mealTime, // Pass meal time from FoodDetails
        image,
      } = food;

      const now = new Date();
      const logDate = now.toISOString().slice(0, 19); // Capture full date and time

      const quantityMultiplier = quantity / 100;

      const adjustedCalories = nf_calories * quantityMultiplier;
      const adjustedProtein = nf_protein * quantityMultiplier;
      const adjustedFiber = nf_dietary_fiber * quantityMultiplier;
      const adjustedCarbs = nf_total_carbohydrate * quantityMultiplier;

      const newMeal = await createMeal(userId, mealNumber, mealTime, logDate);

      // Assuming the response contains the new meal's ID
      const mealId = newMeal[0].meal_id;

      // Create a new meal item (food) for this meal
      const newMealItem = await createMealItem(
        mealId,
        food_name,
        quantity,
        adjustedCalories,
        adjustedProtein,
        adjustedCarbs,
        adjustedFiber
      );

      window.location.href = "/profile";
      // Add the new meal item to the local foodLogs state
      setFoodLogs([...foodLogs, newMealItem]);
    } catch (err) {
      console.error("Error adding food to meal:", err);
      setError("There was a problem adding the food log.");
    }
  };

  const handleEditFood = async (index) => {
    const updatedLogs = [...foodLogs];
    updatedLogs[index].quantity = prompt(
      "Enter new quantity:",
      updatedLogs[index].quantity
    );
    setFoodLogs(updatedLogs);

    // Optionally, you could update the meal item details in the database
    // Call updateMealItem from meal_items.js to sync the changes
  };

  const handleDeleteFood = async (index) => {
    const deletedFood = foodLogs[index];
    setFoodLogs(foodLogs.filter((_, i) => i !== index));

    // Optionally, delete the food log from the backend using deleteMealItem
  };

  if (loading) return <div>Loading...</div>; // Show loading while checking auth status

  return (
    <div className="container mx-auto px-4 py-12">
      <h1 className="text-3xl font-bold mb-8">Food Logs</h1>
      <div className="grid grid-cols-2 gap-4 mb-8">
        <SearchFood
          onSelectFood={handleSelectFood}
          NUTRITIONIX_API_APP_ID={NUTRITIONIX_API_APP_ID}
          NUTRITIONIX_API_APP_KEY={NUTRITIONIX_API_APP_KEY}
        />
        <FoodDetails selectedFood={selectedFood} onAddFood={handleAddFood} />
      </div>
    </div>
  );
};

export default FoodLogs;
