"use client";
import React, { useState, useEffect } from "react";
import {
  updateMealItem,
  getMealItemById,
  deleteMealItem,
} from "@/services/meal_items"; // Import deleteMealItem
import { getMealById, updateMeal, deleteMeal } from "@/services/meals"; // Import deleteMeal
import EditMealItemUI from "./EditMealItemUI";
import { getMealItemsByMeal } from "@/services/meal_items";

const safeNumber = (value) => Number(value) || 0;

export default function EditMealItemLogic({ mealItemId }) {
  const [mealItem, setMealItem] = useState(null);
  const [meal, setMeal] = useState(null);
  const [originalQuantity, setOriginalQuantity] = useState(null);
  const [error, setError] = useState(null);

  // Hooks
  useEffect(() => {
    if (mealItemId) {
      const fetchMealItemData = async () => {
        try {
          const fetchedMealItem = await getMealItemById(mealItemId);
          const mealItemData = Array.isArray(fetchedMealItem)
            ? fetchedMealItem[0]
            : fetchedMealItem;
          setMealItem(mealItemData);

          setOriginalQuantity(safeNumber(mealItemData.food_quantity));

          if (mealItemData.meal_id) {
            const fetchedMeal = await getMealById(mealItemData.meal_id);
            const mealData = Array.isArray(fetchedMeal)
              ? fetchedMeal[0]
              : fetchedMeal;
            setMeal(mealData);
          }
        } catch (err) {
          setError("Error fetching meal item or meal data");
          console.error(err);
        }
      };

      fetchMealItemData();
    }
  }, [mealItemId]);

  const handleUpdateMealItem = async () => {
    try {
      const newQuantity = safeNumber(mealItem.food_quantity);
      if (!newQuantity) throw new Error("Quantity cannot be 0 or empty");

      const scalingFactor = newQuantity / originalQuantity;
      const updatedMealItemInfo = {
        foodName: mealItem.food_name,
        foodQuantity: newQuantity,
        foodCalories: mealItem.food_calories * scalingFactor,
        foodProtein: mealItem.food_protein * scalingFactor,
        foodCarb: mealItem.food_carb * scalingFactor,
        foodFiber: mealItem.food_fiber * scalingFactor,
      };

      const updatedMealItem = await updateMealItem(
        mealItem.meal_item_id,
        updatedMealItemInfo
      );

      setMealItem(updatedMealItem);
      const now = new Date();
      const logDate = now.toISOString().slice(0, 19);

      if (meal) {
        const updateMealInfo = {
          mealNumber: meal.meal_number,
          mealTime: meal.meal_time,
          logDate: logDate,
        };
        const updatedMeal = await updateMeal(meal.meal_id, updateMealInfo);
        setMeal(updatedMeal);
      }

      alert("Meal item and meal updated successfully");
      window.location.href = "http://localhost:3000/profile"; // Redirect after update
    } catch (err) {
      setError("Error updating meal item or meal: " + err.message);
      console.error(err);
    }
  };

  // New delete handler
  const handleDeleteMealItem = async () => {
    try {
      await deleteMealItem(mealItem.meal_item_id); // First, delete the meal item

      // Check if there are any other items left for this meal
      const remainingMealItems = await getMealItemsByMeal(meal.meal_id); // Fetch remaining meal items
      if (remainingMealItems.length === 0) {
        // If no other items remain, delete the meal as well
        await deleteMeal(meal.meal_id);
      }

      alert("Meal item and meal (if no other items) deleted successfully");
      window.location.href = "http://localhost:3000/profile"; // Redirect after update
      // Optionally, redirect or refresh the page after deletion
    } catch (err) {
      setError("Error deleting meal item: " + err.message);
      console.error(err);
    }
  };

  if (error) return <div>{error}</div>;

  if (!mealItem || !meal || originalQuantity === null)
    return <div>Loading...</div>;

  const scalingFactor = mealItem.food_quantity / originalQuantity;
  const updatedNutrition = {
    calories: safeNumber(mealItem.food_calories) * scalingFactor,
    protein: safeNumber(mealItem.food_protein) * scalingFactor,
    carbs: safeNumber(mealItem.food_carb) * scalingFactor,
    fiber: safeNumber(mealItem.food_fiber) * scalingFactor,
  };

  return (
    <EditMealItemUI
      mealItem={mealItem}
      meal={meal}
      updatedNutrition={updatedNutrition}
      handleUpdateMealItem={handleUpdateMealItem}
      handleDeleteMealItem={handleDeleteMealItem} // Pass delete handler to UI
      setMealItem={setMealItem}
      setMeal={setMeal}
      safeNumber={safeNumber}
    />
  );
}
