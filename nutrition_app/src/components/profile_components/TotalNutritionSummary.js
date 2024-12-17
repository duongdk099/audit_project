export default function TotalNutritionSummary({ totalCalories, totalProtein, totalCarbs, totalFiber, totalFat }) {
    // Helper function to format numbers to two decimal places
    const formatNumber = (num) => Number(num).toFixed(2);
  
    return (
      <div className="mt-8 bg-gray-50 p-4 rounded-lg">
        <h2 className="text-xl font-semibold mb-4">Total Nutrition Summary for the Day</h2>
        <div>
          <strong>Calories:</strong> {formatNumber(totalCalories)} kcal<br />
          <strong>Protein:</strong> {formatNumber(totalProtein)}g<br />
          <strong>Carbs:</strong> {formatNumber(totalCarbs)}g<br />
          <strong>Fiber:</strong> {formatNumber(totalFiber)}g<br />
          <strong>Fat:</strong> {formatNumber(totalFat)}g<br />
        </div>
      </div>
    );
  }