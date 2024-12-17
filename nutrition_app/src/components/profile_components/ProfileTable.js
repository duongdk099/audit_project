import React from "react";

// Helper function to safely convert values to numbers and default to 0 if invalid
const safeNumber = (value) => Number(value) || 0;

export default function ProfileTable({ meals }) {
  // Default values for total nutrition if no meals are present
  let totalDailyCalories = 0;
  let totalDailyProtein = 0;
  let totalDailyCarbs = 0;
  let totalDailyFiber = 0;
  let totalDailyFat = 0;

  // Check if meals exist
  const hasMeals = meals && meals.length > 0;

  // If meals exist, calculate the total nutrition
  if (hasMeals) {
    meals.forEach((meal) => {
      meal.foodItems.forEach((food) => {
        totalDailyCalories += safeNumber(food.food_calories);
        totalDailyProtein += safeNumber(food.food_protein);
        totalDailyCarbs += safeNumber(food.food_carb);
        totalDailyFiber += safeNumber(food.food_fiber);
        totalDailyFat += safeNumber(food.food_fat);
      });
    });
  }

  const handleEdit = (mealId) => {
    window.location.href = `/edit-meal/${mealId}`;
  };
  
  return (
    <div className="bg-white p-6 rounded-lg shadow-lg">
      <h2 className="text-2xl font-semibold mb-4">Meals Summary</h2>

      {/* Show meals table if meals exist */}
      {hasMeals ? (
        <table className="min-w-full table-auto">
          <thead>
            <tr className="bg-gray-200 text-gray-600 text-left text-sm uppercase font-semibold">
              <th className="px-4 py-2">What We Ate</th>
              <th className="px-4 py-2">Meal Number</th>
              <th className="px-4 py-2">Time</th>
              <th className="px-4 py-2">Nutrition</th>
              <th className="px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {meals.map((meal) => {
              let mealCalories = 0;
              let mealProtein = 0;
              let mealCarbs = 0;
              let mealFiber = 0;
              let mealFat = 0;

              meal.foodItems.forEach((food) => {
                mealCalories += safeNumber(food.food_calories);
                mealProtein += safeNumber(food.food_protein);
                mealCarbs += safeNumber(food.food_carb);
                mealFiber += safeNumber(food.food_fiber);
                mealFat += safeNumber(food.food_fat);
              });

              return (
                <tr key={meal.meal_id} className="border-b">
                  <td className="px-4 py-2">
                    <ul>
                      {meal.foodItems.map((foodItem, foodIndex) => (
                        <li key={foodIndex}>
                          <strong>{foodItem.food_name}</strong> -{" "}
                          {foodItem.food_quantity}g
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td className="px-4 py-2">Meal {meal.meal_number}</td>
                  <td className="px-4 py-2">{meal.meal_time}</td>
                  <td className="px-4 py-2">
                    Calories: {mealCalories.toFixed(2)} kcal
                    <br />
                    Protein: {mealProtein.toFixed(2)}g
                    <br />
                    Carbs: {mealCarbs.toFixed(2)}g
                    <br />
                    Fiber: {mealFiber.toFixed(2)}g
                    <br />
                    Fat: {mealFat.toFixed(2)}g
                  </td>
                  <td className="px-4 py-2">
                    <button
                      className="bg-yellow-400 text-white px-3 py-1 rounded"
                      onClick={() => handleEdit(meal.meal_id)}
                    >
                      Edit
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div className="text-center text-gray-500 py-4">
          No meals logged for this day.
        </div>
      )}

      {/* Display total nutrition summary for the day */}
      <div className="bg-gray-50 p-4 rounded-lg mt-6">
        <h3 className="text-xl font-semibold mb-2">
          Total Nutrition for the Day
        </h3>
        <p>Calories: {totalDailyCalories.toFixed(2)} kcal</p>
        <p>Protein: {totalDailyProtein.toFixed(2)}g</p>
        <p>Carbohydrates: {totalDailyCarbs.toFixed(2)}g</p>
        <p>Fiber: {totalDailyFiber.toFixed(2)}g</p>
        <p>Fat: {totalDailyFat.toFixed(2)}g</p>
      </div>
    </div>
  );
}
