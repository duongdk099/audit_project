import { useState, useEffect } from "react";
import Cookies from "js-cookie";
import { getMealsByUser } from "@/services/meals";
import { getMealItemsByMeal } from "@/services/meal_items";

export function useProfileData(selectedDate, sortOption) {
  const [meals, setMeals] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const authToken = Cookies.get("authToken");

    if (!authToken || authToken === "") {
      setError("You are not logged in. Please log in first.");
      setLoading(false);
      return;
    }

    const object_authToken = JSON.parse(authToken);
    const userId = object_authToken.user_id;

    const fetchMeals = async () => {
      try {
        const userMeals = await getMealsByUser(userId);

        const formatDateLocal = (dateString) => {
          const date = new Date(dateString);
          const year = date.getFullYear();
          const month = String(date.getMonth() + 1).padStart(2, "0");
          const day = String(date.getDate()).padStart(2, "0");
          return `${year}-${month}-${day}`;
        };

        const filteredMeals = userMeals.filter(
          (meal) =>
            formatDateLocal(meal.log_date) === formatDateLocal(selectedDate)
        );

        const mealDataWithItems = await Promise.all(
          filteredMeals.map(async (meal) => {
            const foodItems = await getMealItemsByMeal(meal.meal_id);
            return { ...meal, foodItems };
          })
        );

        // Sort meals based on the selected sort option
        let sortedMeals = mealDataWithItems;
        if (sortOption === "meal_number") {
          sortedMeals = mealDataWithItems.sort(
            (a, b) => a.meal_number - b.meal_number
          );
        } else if (sortOption === "meal_time") {
          sortedMeals = mealDataWithItems.sort((a, b) => {
            const timeA = new Date(`1970-01-01T${a.meal_time}`).getTime();
            const timeB = new Date(`1970-01-01T${b.meal_time}`).getTime();
            return timeA - timeB; // Compare as timestamps
          });
        }

        setMeals(sortedMeals.length > 0 ? sortedMeals : []);
        setLoading(false);
      } catch (err) {
        setError("Failed to load meals data");
        console.error("Error:", err);
        setLoading(false);
      }
    };

    fetchMeals();
  }, [selectedDate, sortOption]);

  return { meals, error, loading };
}
