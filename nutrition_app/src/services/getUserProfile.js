import { getMealLogsByUser } from './mealLogs';
import { getMealLogItemsByLog } from './mealLogItems';
import { getAllFoodItems } from './foodItems'; 

export const getUserProfile = async (userId) => {
  try {
    // Step 1: Fetch all meal logs for the user
    const mealLogs = await getMealLogsByUser(userId);

    // Step 2: Fetch all food items and create a food item map for quick lookup by ID
    const allFoodItems = await getAllFoodItems();
    const foodItemMap = {};
    allFoodItems.forEach(foodItem => {
      foodItemMap[foodItem.food_id] = foodItem;  // Create a map with food_id as the key
    });

    // Step 3: Build the full meal logs with food items and nutrition info
    const foodLogs = [];
    let totalNutrition = {
      calories: 0,
      protein: 0,
      carbs: 0,
      fiber: 0,
      fat: 0,  // Assuming we also want to track fat
    };

    for (const mealLog of mealLogs) {
      // Fetch meal log items for each meal
      const mealLogItems = await getMealLogItemsByLog(mealLog.meal_log_id);

      const mealFoods = mealLogItems.map(item => {
        const foodItem = foodItemMap[item.food_id];
        // Calculate total nutrition for this meal log item
        totalNutrition.calories += foodItem.calories;
        totalNutrition.protein += foodItem.protein;
        totalNutrition.carbs += foodItem.carbs;
        totalNutrition.fiber += foodItem.fiber;

        return {
          food_name: foodItem.food_name,
          quantity_in_grams: item.consumed_quantity_in_grams,
          calories: foodItem.calories,
          protein: foodItem.protein,
          carbs: foodItem.carbs,
          fiber: foodItem.fiber,
        };
      });

      // Add the meal and its foods to the foodLogs array
      foodLogs.push({
        meal_number: mealLog.meal_number,
        meal_time: mealLog.meal_time,
        foods: mealFoods,
      });
    }

    // Step 4: Return the full user profile including food logs and nutrition summary
    return {
      name: 'John Doe',  // Replace with real user info if necessary
      email: 'john.doe@example.com',  // Replace with real user info if necessary
      foodLogs: foodLogs,  // What the user ate, meal number, meal time
      nutrition: totalNutrition,  // Total calories, protein, carbs, fiber, fat
    };
  } catch (error) {
    console.error('Error fetching user profile:', error);
    throw error;
  }
};