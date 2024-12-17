const CustomizeIngredients = ({ ingredients, customQuantities, handleCustomQuantityChange, handleAddToMeal }) => (
    <div className="max-w-4xl mx-auto bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-semibold mb-4">Customize Ingredient Quantities</h2>
  
      {/* Editable ingredients in the additional box */}
      <ul className="space-y-4">
        {ingredients.map((ingredient, index) => (
          <li key={index} className="flex justify-between items-center">
            <span className="text-gray-700">{ingredient.name}</span>
            <input
              type="number"
              value={customQuantities[index]}
              onChange={(e) => handleCustomQuantityChange(e, index)}
              className="w-24 px-4 py-2 border rounded-lg"
            />
            <span className="text-gray-700">{ingredient.unit}</span>
          </li>
        ))}
      </ul>
  
      {/* Add to Meal Button */}
      <div className="mt-4 text-right">
        <button
          onClick={handleAddToMeal}
          className="bg-blue-500 text-white py-2 px-6 rounded hover:bg-blue-600 transition duration-300"
        >
          Add to Your Meal of the Day
        </button>
      </div>
    </div>
  );
  
  export default CustomizeIngredients;