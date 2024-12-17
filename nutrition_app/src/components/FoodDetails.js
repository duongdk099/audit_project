import { useState } from "react";

const FoodDetails = ({ selectedFood, onAddFood }) => {
  const [quantity, setQuantity] = useState(100); // default quantity in grams
  const [mealNumber, setMealNumber] = useState(1); // default meal number
  const [mealTime, setMealTime] = useState("08:00"); // default meal time

  const handleAddFood = () => {
    // Ensure correct mapping of selected food details to required fields
    const foodToAdd = {
      food_name: selectedFood.name, // foodName
      nf_calories: selectedFood.calories, 
      nf_protein: selectedFood.protein, 
      nf_dietary_fiber: selectedFood.fiber, 
      nf_total_carbohydrate: selectedFood.carbs, 
      image: selectedFood.image,
      quantity, // User-defined quantitys
      mealNumber, // User-defined meal number
      mealTime, // User-defined meal time
    };

    onAddFood(foodToAdd);
  
    // Reset the form after adding the food
    setQuantity(100);
    setMealNumber(1);
    setMealTime("08:00");
  };

  return selectedFood ? (
    <div className="p-4 border rounded">
      <h2 className="text-xl font-bold mb-4">{selectedFood.name}</h2>

      {/* Display food image if available */}
      {selectedFood.image && (
        <img
          src={selectedFood.image}
          alt={selectedFood.name}
          className="w-32 h-32 object-cover mb-4"
        />
      )}

      <div className="grid grid-cols-2 gap-4">
        <div>
          <p>Calories (per 100g): {selectedFood.calories}</p>
          <p>Protein: {selectedFood.protein} g</p>
        </div>
        <div>
          <p>Fiber: {selectedFood.fiber} g</p>
          <p>Carbs: {selectedFood.carbs} g</p>
        </div>
      </div>

      <div className="mt-4">
        <label className="block mb-2">Quantity (in grams):</label>
        <input
          type="number"
          value={quantity}
          onChange={(e) => setQuantity(e.target.value)}
          className="w-full p-2 border rounded"
        />

        <label className="block mt-4 mb-2">Meal Number:</label>
        <input
          type="number"
          value={mealNumber}
          onChange={(e) => setMealNumber(e.target.value)}
          className="w-full p-2 border rounded"
        />

        <label className="block mt-4 mb-2">Meal Time:</label>
        <input
          type="time"
          value={mealTime}
          onChange={(e) => setMealTime(e.target.value)}
          className="w-full p-2 border rounded"
        />

        <button
          onClick={handleAddFood}
          className="mt-4 w-full p-2 bg-blue-500 text-white rounded"
        >
          Add Food Item
        </button>
      </div>
    </div>
  ) : null;
};

export default FoodDetails;