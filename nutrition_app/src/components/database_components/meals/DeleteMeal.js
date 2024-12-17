import { useState } from "react";
import { deleteMeal } from "@/services/meals";

const DeleteMeal = () => {
  const [mealId, setMealId] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const deletedMeal = await deleteMeal(mealId);
      setSuccess("Meal deleted successfully!");
      setMealId("");
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
        <button type="submit">Delete Meal</button>
      </form>
    </div>
  );
};

export default DeleteMeal;