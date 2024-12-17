import { useEffect, useState } from "react";
import { getMealItems } from "@/services/meal_items";

const ReadMealItems = () => {
  const [mealItems, setMealItems] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchMealItems = async () => {
      try {
        const mealItemsData = await getMealItems();
        setMealItems(mealItemsData);
      } catch (error) {
        setError(error.message);
      }
    };
    fetchMealItems();
  }, []);

  return (
    <div>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Meal Item ID</th>
            <th>Meal ID</th>
            <th>Food Name</th>
            <th>Quantity</th>
            <th>Calories</th>
            <th>Protein</th>
            <th>Carbs</th>
            <th>Fiber</th>
          </tr>
        </thead>
        <tbody>
          {mealItems.map((mealItem) => (
            <tr key={mealItem.meal_item_id}>
              <td>{mealItem.meal_item_id}</td>
              <td>{mealItem.meal_id}</td>
              <td>{mealItem.food_name}</td>
              <td>{mealItem.food_quantity}</td>
              <td>{mealItem.food_calories}</td>
              <td>{mealItem.food_protein}</td>
              <td>{mealItem.food_carb}</td>
              <td>{mealItem.food_fiber}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default ReadMealItems;