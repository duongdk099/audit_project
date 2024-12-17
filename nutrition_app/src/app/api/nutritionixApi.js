export const selectFoodItem = async (foodName, appId, appKey) => {
  try {
    const res = await fetch(
      "https://trackapi.nutritionix.com/v2/natural/nutrients",
      {
        method: "POST",
        headers: {
          "x-app-id": appId,
          "x-app-key": appKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: foodName,
        }),
      }
    );

    const data = await res.json();

    if (data.foods && data.foods.length > 0) {
      const nutrientData = data.foods[0];
      return {
        name: nutrientData.food_name,
        calories: nutrientData.nf_calories || 0,
        protein: nutrientData.nf_protein || 0,
        fiber: nutrientData.nf_dietary_fiber || 0,
        carbs: nutrientData.nf_total_carbohydrate || 0,
        image: nutrientData.photo.thumb ? nutrientData.photo.thumb : null,
      };
    }

    return null;
  } catch (error) {
    console.error("Error fetching nutritional data from Nutritionix:", error);
    return null;
  }
};

// Add this to api/nutritionixApi.js

export const searchFoodItems = async (searchTerm, appId, appKey) => {
  if (searchTerm.length < 3) {
    return []; // Return an empty array if search term is too short
  }

  try {
    const res = await fetch(
      `https://trackapi.nutritionix.com/v2/search/instant?query=${searchTerm}`,
      {
        headers: {
          "x-app-id": appId,
          "x-app-key": appKey,
          "x-remote-user-id": "0",
        },
      }
    );

    const data = await res.json();

    // Map the search results to a list of food names
    const commonFoods = data.common.map((food) => ({
      name: food.food_name,
    }));

    return commonFoods;
  } catch (error) {
    console.error("Error fetching search results from Nutritionix:", error);
    return [];
  }
};
