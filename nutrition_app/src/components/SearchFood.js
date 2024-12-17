import { useState } from "react";
import { searchFoodItems } from "../app/api/nutritionixApi"; // Import the new search API

const SearchFood = ({ onSelectFood, NUTRITIONIX_API_APP_ID, NUTRITIONIX_API_APP_KEY }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [foodDatabase, setFoodDatabase] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e) => {
    setSearchTerm(e.target.value);

    if (e.target.value.length > 2) {
      setLoading(true);
      const commonFoods = await searchFoodItems(e.target.value, NUTRITIONIX_API_APP_ID, NUTRITIONIX_API_APP_KEY);
      setFoodDatabase(commonFoods);
      setLoading(false);
    } else {
      setFoodDatabase([]); // Clear results if search term is too short
    }
  };

  return (
    <div>
      <input
        type="text"
        value={searchTerm}
        onChange={handleSearch}
        className="w-full p-4 border rounded"
        placeholder="Search for food item..."
      />
      <ul className="mt-4 space-y-2">
        {loading ? (
          <li>Loading...</li>
        ) : (
          foodDatabase
            .slice(0, 10) // Show only the first 10 results
            .map((food, index) => (
              <li
                key={index}
                className="p-2 border rounded cursor-pointer hover:bg-gray-200"
                onClick={() => onSelectFood(food)}
              >
                {food.name}
              </li>
            ))
        )}
      </ul>
    </div>
  );
};

export default SearchFood;