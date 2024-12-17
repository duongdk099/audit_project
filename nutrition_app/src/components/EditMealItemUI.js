"use client";
import React from 'react';

export default function EditMealItemUI({
  mealItem,
  meal,
  updatedNutrition,
  handleUpdateMealItem,
  handleDeleteMealItem, // Add delete handler
  setMealItem,
  setMeal,
  safeNumber
}) {
  return (
    <div className="container mx-auto p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-4 text-gray-800">Edit Meal Item</h2>
      <div className="p-4 bg-gray-100 rounded-lg shadow-lg grid grid-cols-2 gap-4">
        {/* Left Box: Updated Nutrition Information */}
        <div className="bg-blue-100 p-4 rounded-lg shadow">
          <h3 className="font-semibold text-lg text-gray-700">Updated Nutrition</h3>
          <p>Calories: {safeNumber(mealItem.food_calories).toFixed(2)} kcal</p>
          <p>Protein: {safeNumber(mealItem.food_protein).toFixed(2)} g</p>
          <p>Carbs: {safeNumber(mealItem.food_carb).toFixed(2)} g</p>
          <p>Fiber: {safeNumber(mealItem.food_fiber).toFixed(2)} g</p>
        </div>

        {/* Right Box: Updated Nutrition After Change */}
        <div className="bg-green-100 p-4 rounded-lg shadow">
          <h3 className="font-semibold text-lg text-gray-700">New Nutrition After Change</h3>
          <p>Calories: {updatedNutrition.calories.toFixed(2)} kcal</p>
          <p>Protein: {updatedNutrition.protein.toFixed(2)} g</p>
          <p>Carbs: {updatedNutrition.carbs.toFixed(2)} g</p>
          <p>Fiber: {updatedNutrition.fiber.toFixed(2)} g</p>
        </div>
      </div>

      <div className="p-4 bg-gray-100 rounded-lg shadow-lg mt-4">
        <div className="grid grid-cols-1 gap-4">
          {/* Food Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700">Food Name</label>
            <p className="mt-1 text-gray-900 font-semibold">{mealItem.food_name}</p>
          </div>

          {/* Quantity */}
          <div>
            <label className="block text-sm font-medium text-gray-700">Quantity (g)</label>
            <input
              type="number"
              value={mealItem.food_quantity || ''}
              onChange={(e) => setMealItem({ ...mealItem, food_quantity: safeNumber(e.target.value) })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
            />
          </div>

          {/* Meal Number */}
          <div>
            <label className="block text-sm font-medium text-gray-700">Meal Number</label>
            <input
              type="number"
              value={meal.meal_number || ''}
              onChange={(e) => setMeal({ ...meal, meal_number: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
            />
          </div>

          {/* Meal Time */}
          <div>
            <label className="block text-sm font-medium text-gray-700">Meal Time</label>
            <input
              type="time"
              value={meal.meal_time || ''}
              onChange={(e) => setMeal({ ...meal, meal_time: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm"
            />
          </div>
        </div>

        <button
          onClick={handleUpdateMealItem}
          className="mt-4 w-full bg-green-500 text-white py-2 px-4 rounded-md shadow hover:bg-green-600 transition duration-300"
        >
          Update Meal Item and Meal
        </button>

        {/* Delete Button */}
        <button
          onClick={handleDeleteMealItem}
          className="mt-2 w-full bg-red-500 text-white py-2 px-4 rounded-md shadow hover:bg-red-600 transition duration-300"
        >
          Delete Meal Item
        </button>
      </div>
    </div>
  );
}