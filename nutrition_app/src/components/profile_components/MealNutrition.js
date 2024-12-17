export default function MealNutrition({ calories, protein, carbs, fiber, fat }) {
    // Helper function to format numbers to two decimal places
    const formatNumber = (num) => Number(num).toFixed(2);
  
    return (
      <div>
        <strong>Calories:</strong> {formatNumber(calories)} kcal<br />
        <strong>Protein:</strong> {formatNumber(protein)}g<br />
        <strong>Carbs:</strong> {formatNumber(carbs)}g<br />
        <strong>Fiber:</strong> {formatNumber(fiber)}g<br />
        <strong>Fat:</strong> {formatNumber(fat)}g<br />
      </div>
    );
  }