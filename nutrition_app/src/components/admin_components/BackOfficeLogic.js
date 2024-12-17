// BackOfficeLogic.js
import { useState, useEffect } from "react";
import { getUsers, createUser, updateUser, deleteUser } from "@/services/users";
import { getMeals, createMeal, updateMeal, deleteMeal } from "@/services/meals";
import {
  getMealItems,
  createMealItem,
  updateMealItem,
  deleteMealItem,
} from "@/services/meal_items";

export const useBackOfficeLogic = () => {
  const [users, setUsers] = useState([]);
  const [meals, setMeals] = useState([]);
  const [mealItems, setMealItems] = useState([]);

  const [newUser, setNewUser] = useState({
    username: "",
    email: "",
    password: "",
  });
  const [newMeal, setNewMeal] = useState({
    user_id: "",
    meal_number: "",
    meal_time: "",
    log_date: "",
  });
  const [newMealItem, setNewMealItem] = useState({
    meal_id: "",
    food_name: "",
    food_quantity: "",
    food_calories: "",
    food_protein: "",
    food_carb: "",
    food_fiber: "",
  });

  useEffect(() => {
    const fetchData = async () => {
      const fetchedUsers = await getUsers();
      const fetchedMeals = await getMeals();
      const fetchedMealItems = await getMealItems();
      setUsers(fetchedUsers);
      setMeals(fetchedMeals);
      setMealItems(fetchedMealItems);
    };
    fetchData();
  }, []);

  // CRUD operations for users
  const handleCreateUser = async (e) => {
    e.preventDefault();
    const newUserResponse = await createUser(
      newUser.username,
      newUser.email,
      newUser.password
    );
    setUsers([...users, newUserResponse]);
    setNewUser({ username: "", email: "", password: "" });
  };

  const handleUpdateUser = async (userId, updatedData) => {
    const updatedUser = await updateUser(userId, updatedData);
    setUsers(
      users.map((user) => (user.user_id === userId ? updatedUser : user))
    );
  };

  const handleDeleteUser = async (userId) => {
    await deleteUser(userId);
    setUsers(users.filter((user) => user.user_id !== userId));
  };

  // CRUD operations for meals
  const handleCreateMeal = async (e) => {
    e.preventDefault();
    const newMealResponse = await createMeal(
      newMeal.user_id,
      newMeal.meal_number,
      newMeal.meal_time,
      newMeal.log_date
    );
    setMeals([...meals, newMealResponse]);
    setNewMeal({ user_id: "", meal_number: "", meal_time: "", log_date: "" });
  };

  const handleUpdateMeal = async (mealId, updatedData) => {
    const updatedMeal = await updateMeal(mealId, updatedData);
    setMeals(
      meals.map((meal) => (meal.meal_id === mealId ? updatedMeal : meal))
    );
  };

  const handleDeleteMeal = async (mealId) => {
    await deleteMeal(mealId);
    setMeals(meals.filter((meal) => meal.meal_id !== mealId));
  };

  // CRUD operations for meal items
  const handleCreateMealItem = async (e) => {
    e.preventDefault();
    const newMealItemResponse = await createMealItem(
      newMealItem.meal_id,
      newMealItem.food_name,
      newMealItem.food_quantity,
      newMealItem.food_calories,
      newMealItem.food_protein,
      newMealItem.food_carb,
      newMealItem.food_fiber
    );
    setMealItems([...mealItems, newMealItemResponse]);
    setNewMealItem({
      meal_id: "",
      food_name: "",
      food_quantity: "",
      food_calories: "",
      food_protein: "",
      food_carb: "",
      food_fiber: "",
    });
  };

  const handleUpdateMealItem = async (mealItemId, updatedData) => {
    const updatedDataMealItem = {
      food_name: updatedData.food_name,
      food_quantity: updatedData.food_quantity,
      food_calories: updatedData.food_calories,
      food_protein: updatedData.food_protein,
      food_carb: updatedData.food_carb,
      food_fiber: updatedData.food_fiber,
    };
    const updatedMealItem = await updateMealItem(
      mealItemId,
      updatedDataMealItem
    );
    setMealItems(
      mealItems.map((mealItem) =>
        mealItem.meal_item_id === mealItemId ? updatedMealItem : mealItem
      )
    );
  };

  const handleDeleteMealItem = async (mealItemId) => {
    await deleteMealItem(mealItemId);
    setMealItems(
      mealItems.filter((mealItem) => mealItem.meal_item_id !== mealItemId)
    );
  };

  return {
    users,
    meals,
    mealItems,
    newUser,
    newMeal,
    newMealItem,
    setNewUser,
    setNewMeal,
    setNewMealItem,
    handleCreateUser,
    handleUpdateUser,
    handleDeleteUser,
    handleCreateMeal,
    handleUpdateMeal,
    handleDeleteMeal,
    handleCreateMealItem,
    handleUpdateMealItem,
    handleDeleteMealItem,
  };
};
