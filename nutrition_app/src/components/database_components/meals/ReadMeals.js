import { useEffect, useState } from "react";
import { getMeals } from "@/services/meals";

const ReadMeals = () => {
  const [meals, setMeals] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchMeals = async () => {
      try {
        const mealData = await getMeals();
        setMeals(mealData);
      } catch (error) {
        setError(error.message);
      }
    };
    fetchMeals();
  }, []);

  return (
    <div>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Meal ID</th>
            <th>User ID</th>
            <th>Meal Number</th>
            <th>Meal Time</th>
            <th>Log Date</th>
          </tr>
        </thead>
        <tbody>
          {meals.map((meal) => (
            <tr key={meal.meal_id}>
              <td>{meal.meal_id}</td>
              <td>{meal.user_id}</td>
              <td>{meal.meal_number}</td>
              <td>{meal.meal_time}</td>
              <td>{meal.log_date}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ReadMeals;