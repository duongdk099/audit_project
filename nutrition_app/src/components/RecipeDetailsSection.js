const RecipeDetailsSection = ({ ingredients, instructions, nutrition }) => (
  <>
    {/* Ingredients Section */}
    <div className="max-w-4xl mx-auto bg-white p-6 rounded-lg shadow-md mb-8">
      <h2 className="text-2xl font-semibold mb-4">Ingredients</h2>
      <ul className="list-disc list-inside space-y-2">
        {ingredients.map((ingredient, index) => (
          <li key={index} className="text-gray-700">
            {ingredient.quantity} {ingredient.unit} {ingredient.name}
          </li>
        ))}
      </ul>
    </div>

    {/* Instructions Section */}
    <div className="max-w-4xl mx-auto bg-white p-6 rounded-lg shadow-md mb-8">
      <h2 className="text-2xl font-semibold mb-4">Instructions</h2>
      <ol className="list-decimal list-inside space-y-2">
        {instructions.map((step, index) => (
          <li key={index} className="text-gray-700">{step}</li>
        ))}
      </ol>
    </div>

    {/* Nutritional Information */}
    <div className="max-w-4xl mx-auto bg-white p-6 rounded-lg shadow-md mb-8">
      <h2 className="text-2xl font-semibold mb-4">Nutritional Information</h2>
      <div className="grid grid-cols-3 gap-4">
        <div>
          <h3 className="text-lg font-medium">Calories</h3>
          <p>{nutrition.calories} kcal</p>
        </div>
        <div>
          <h3 className="text-lg font-medium">Protein</h3>
          <p>{nutrition.protein}</p>
        </div>
        <div>
          <h3 className="text-lg font-medium">Fat</h3>
          <p>{nutrition.fat}</p>
        </div>
        <div>
          <h3 className="text-lg font-medium">Carbohydrates</h3>
          <p>{nutrition.carbs}</p>
        </div>
      </div>
    </div>
  </>
);

export default RecipeDetailsSection;