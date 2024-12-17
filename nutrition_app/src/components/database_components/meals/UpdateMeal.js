"use client";
import { useState, useEffect } from "react";
import { updateMeal, getMealById } from "@/services/meals"; // Import getMealById function

const UpdateMeal = ({ mealId }) => {
  const [mealNumber, setMealNumber] = useState("");
  const [mealTime, setMealTime] = useState("");
  const [logDate, setLogDate] = useState(() => {
    // Initialize logDate with today's date in "YYYY-MM-DD" format
    const today = new Date();
    return today.toISOString().split('T')[0];
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Fetch meal data and pre-fill form fields
  useEffect(() => {
    const fetchMeal = async () => {
      try {
        const meal = await getMealById(mealId); // Fetch the meal by ID
        if (meal && meal.length > 0) {
          setMealNumber(meal[0].meal_number);
          setMealTime(meal[0].meal_time);
          setLogDate(meal.log_date || logDate); // Use fetched logDate or default to current day
          
        } else {
          setError("Meal not found");
        }
      } catch (err) {
        setError("Error fetching meal data");
      }
    };
    if (mealId) {
      fetchMeal();
    }
  }, [mealId]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const updatedData = {
      mealNumber,
      mealTime,
      logDate,
    };

    try {
      const updatedMeal = await updateMeal(mealId, updatedData);
      setSuccess("Meal updated successfully!");
    } catch (error) {
      setError(error.message);
    }
  };

  return (
    <div className="max-w-lg mx-auto bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold text-center mb-6">Update Meal</h2>
      {error && <p className="text-red-500 text-center mb-4">{error}</p>}
      {success && <p className="text-green-500 text-center mb-4">{success}</p>}
      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="flex flex-col">
          <label htmlFor="mealId" className="mb-2 text-gray-700">Meal ID</label>
          <input
            type="text"
            id="mealId"
            value={mealId}
            readOnly
            className="p-2 border border-gray-300 rounded-md bg-gray-200 cursor-not-allowed"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="mealNumber" className="mb-2 text-gray-700">Meal Number</label>
          <input
            type="text"
            id="mealNumber"
            placeholder="Meal Number"
            value={mealNumber}
            onChange={(e) => setMealNumber(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="mealTime" className="mb-2 text-gray-700">Meal Time</label>
          <input
            type="text"
            id="mealTime"
            placeholder="Meal Time"
            value={mealTime}
            onChange={(e) => setMealTime(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="logDate" className="mb-2 text-gray-700">Log Date</label>
          <input
            type="date"
            id="logDate"
            value={logDate}
            onChange={(e) => setLogDate(e.target.value)}
            required
            className="p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-blue-500 text-white py-2 rounded-md hover:bg-blue-600 transition duration-300"
        >
          Update Meal
        </button>
      </form>
    </div>
  );
};

export default UpdateMeal;