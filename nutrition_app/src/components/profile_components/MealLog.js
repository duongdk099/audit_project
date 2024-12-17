import MealNutrition from './MealNutrition';

export default function MealLog({ log, mealNumber }) {
  // Helper function to safely convert values to numbers and default to 0 if invalid
  const safeNumber = (value) => Number(value) || 0;

  // Calculate total nutrition for this meal
  const totalCalories = log.foods?.reduce((sum, food) => sum + safeNumber(food.calories), 0);
  const totalProtein = log.foods?.reduce((sum, food) => sum + safeNumber(food.protein), 0);
  const totalCarbs = log.foods?.reduce((sum, food) => sum + safeNumber(food.carbs), 0);
  const totalFiber = log.foods?.reduce((sum, food) => sum + safeNumber(food.fiber), 0);
  const totalFat = log.foods?.reduce((sum, food) => sum + safeNumber(food.fat), 0);

  return (
    <div className="grid grid-cols-3 gap-4 mt-4">
      {/* Left Column: What We Ate */}
      <div>
        <ul>
          {log.foods?.map((food, i) => (
            <li key={i}>
              <strong>{food.food_name}</strong> - {safeNumber(food.quantity_in_grams)}g
            </li>
          ))}
        </ul>
      </div>

      {/* Middle Column: Meal Number and Time */}
      <div>
        <strong>Meal {mealNumber}:</strong> {log.meal_time}
      </div>

      {/* Right Column: Meal Nutrition */}
      <MealNutrition
        calories={totalCalories}
        protein={totalProtein}
        carbs={totalCarbs}
        fiber={totalFiber}
        fat={totalFat}
      />
    </div>
  );
}