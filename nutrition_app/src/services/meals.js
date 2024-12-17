import { neon } from '@neondatabase/serverless';

// Create a new meal
export async function createMeal(user_id, meal_number, meal_time, log_date) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const newMeal = await sql`
        INSERT INTO meals (user_id, meal_number, meal_time, log_date)
        VALUES (${user_id}, ${meal_number}, ${meal_time}, ${log_date})
        RETURNING *;
    `;
    return newMeal;
}

// Read (Get) all meals
export async function getMeals() {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const meals = await sql`SELECT * FROM meals`;
    return meals;
}
// Read (Get) meals by user_id
export async function getMealsByUser(user_id) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const meals = await sql`
        SELECT * FROM meals
        WHERE user_id = ${user_id};
    `;
    return meals;
}

// Read (Get) a specific meal by meal_id
export async function getMealById(meal_id) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const meal = await sql`
        SELECT * FROM meals
        WHERE meal_id = ${meal_id};
    `;
    return meal;
}

// Update a meal
export async function updateMeal(mealId, updatedData) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const { mealNumber, mealTime, logDate } = updatedData;
  
    const updatedMeal = await sql`
      UPDATE meals
      SET 
        meal_number = ${mealNumber}, 
        meal_time = ${mealTime}, 
        log_date = ${logDate}
      WHERE meal_id = ${mealId}
      RETURNING *;
    `;
  
    return updatedMeal;
  }

// Delete a meal
export async function deleteMeal(meal_id) {
    const sql = neon(process.env.NEXT_PUBLIC_DATABASE_URL);
    const deletedMeal = await sql`
        DELETE FROM meals
        WHERE meal_id = ${meal_id}
        RETURNING *;
    `;
    return deletedMeal;
}