import { neon } from '@neondatabase/serverless';

// Create a new meal item (food within a meal)
export async function createMealItem(meal_id, food_name, food_quantity, food_calories, food_protein, food_carb, food_fiber) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const newMealItem = await sql`
        INSERT INTO meal_items (meal_id, food_name, food_quantity, food_calories, food_protein, food_carb, food_fiber)
        VALUES (${meal_id}, ${food_name}, ${food_quantity}, ${food_calories}, ${food_protein}, ${food_carb}, ${food_fiber})
        RETURNING *;
    `;
    return newMealItem;
}

// Read (Get) all meal items
export async function getMealItems() {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const mealItems = await sql`SELECT * FROM meal_items`;
    return mealItems;
}
// Read (Get) all meal items for a specific meal
export async function getMealItemsByMeal(meal_id) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const mealItems = await sql`
        SELECT * FROM meal_items
        WHERE meal_id = ${meal_id};
    `;
    return mealItems;
}

// Read (Get) a specific meal item by meal_item_id
export async function getMealItemById(meal_item_id) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const mealItem = await sql`
        SELECT * FROM meal_items
        WHERE meal_item_id = ${meal_item_id};
    `;
    return mealItem[0];
}

// Update a meal item (food details)
export async function updateMealItem(mealItemId, updatedData) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const { foodName, foodQuantity, foodCalories, foodProtein, foodCarb, foodFiber } = updatedData;
  
    const updatedMealItem = await sql`
      UPDATE meal_items
      SET 
        food_name = ${foodName},
        food_quantity = ${foodQuantity},
        food_calories = ${foodCalories},
        food_protein = ${foodProtein},
        food_carb = ${foodCarb},
        food_fiber = ${foodFiber}
      WHERE meal_item_id = ${mealItemId}
      RETURNING *;
    `;
  
    return updatedMealItem;
  }

// Delete a meal item
export async function deleteMealItem(meal_item_id) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const deletedMealItem = await sql`
        DELETE FROM meal_items
        WHERE meal_item_id = ${meal_item_id}
        RETURNING *;
    `;
    return deletedMealItem;
}