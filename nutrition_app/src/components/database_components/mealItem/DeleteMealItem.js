import { useState } from "react";
import { deleteMealItem } from "@/services/meal_items";

const DeleteMealItem = () => {
  const [mealItemId, setMealItemId] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const deletedMealItem = await deleteMealItem(mealItemId);
      setSuccess("Meal item deleted successfully!");
      setMealItemId("");
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
          placeholder="Meal Item ID"
          value={mealItemId}
          onChange={(e) => setMealItemId(e.target.value)}
          required
        />
        <button type="submit">Delete Meal Item</button>
      </form>
    </div>
  );
};

export default DeleteMealItem;