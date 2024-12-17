import { useState } from "react";
import { createMealItem } from "@/services/meal_items";

const CreateMealItem = () => {
  const [mealId, setMealId] = useState("");
  const [foodName, setFoodName] = useState("");
  const [foodQuantity, setFoodQuantity] = useState("");
  const [foodCalories, setFoodCalories] = useState("");
  const [foodProtein, setFoodProtein] = useState("");
  const [foodCarb, setFoodCarb] = useState("");
  const [foodFiber, setFoodFiber] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const newMealItem = await createMealItem(mealId, foodName, foodQuantity, foodCalories, foodProtein, foodCarb, foodFiber);
      setSuccess("Meal item created successfully!");
      setMealId("");
      setFoodName("");
      setFoodQuantity("");
      setFoodCalories("");
      setFoodProtein("");
      setFoodCarb("");
      setFoodFiber("");
    } catch (error) {
      setError(error.message);
    }
  };

  return (
    <div>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {success && <p style={{ color: "green" }}>{success}</p>}
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Meal ID"
          value={mealId}
          onChange={(e) => setMealId(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Food Name"
          value={foodName}
          onChange={(e) => setFoodName(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Quantity"
          value={foodQuantity}
          onChange={(e) => setFoodQuantity(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Calories"
          value={foodCalories}
          onChange={(e) => setFoodCalories(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Protein"
          value={foodProtein}
          onChange={(e) => setFoodProtein(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Carbs"
          value={foodCarb}
          onChange={(e) => setFoodCarb(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Fiber"
          value={foodFiber}
          onChange={(e) => setFoodFiber(e.target.value)}
          required
        />
        <button type="submit">Create Meal Item</button>
      </form>
    </div>
  );
};

export default CreateMealItem;