import { useState } from "react";
import { createMeal } from "@/services/meals";

const CreateMeal = () => {
  const [userId, setUserId] = useState("");
  const [mealNumber, setMealNumber] = useState("");
  const [mealTime, setMealTime] = useState("");
  const [logDate, setLogDate] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const newMeal = await createMeal(userId, mealNumber, mealTime, logDate);
      setSuccess("Meal created successfully!");
      setUserId("");
      setMealNumber("");
      setMealTime("");
      setLogDate("");
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
          placeholder="User ID"
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Meal Number"
          value={mealNumber}
          onChange={(e) => setMealNumber(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Meal Time"
          value={mealTime}
          onChange={(e) => setMealTime(e.target.value)}
          required
        />
        <input
          type="date"
          placeholder="Log Date"
          value={logDate}
          onChange={(e) => setLogDate(e.target.value)}
          required
        />
        <button type="submit">Create Meal</button>
      </form>
    </div>
  );
};

export default CreateMeal;