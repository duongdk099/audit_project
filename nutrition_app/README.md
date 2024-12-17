
# 🍽️ Nutrition Website

This is a **Next.js** and **Tailwind CSS** based project that provides a dynamic nutrition information platform. The application allows users to explore nutrition data, manage user sessions, and access various features with the help of `Neon` and other APIs.

## 📋 Table of Contents

- [🚀 Getting Started](#getting-started)
- [✨ Features](#features)
- [📁 Project Structure](#project-structure)
- [🗄️ Database Structure](#database-structure)
- [🔑 Environment Variables](#environment-variables)
- [📜 Scripts](#scripts)
- [📦 Dependencies](#dependencies)
- [🛠️ Technologies Used](#technologies-used)
- [📜 License](#license)
- [🙏 Acknowledgments](#acknowledgments)

## 🚀 Getting Started

To set up a local copy, follow these instructions.

### ⚙️ Prerequisites

- **Node.js**: Download and install the latest LTS version from [nodejs.org](https://nodejs.org).
- **npm or Yarn**: This project uses npm by default.

### 📥 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/nutrition-website.git
   cd nutrition-website
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Set up Environment Variables**  
   Create a `.env` file in the root directory with the required environment variables (detailed below).

4. **Run Development Server**
   ```bash
   npm run dev
   ```
   Access the app at [http://localhost:3000](http://localhost:3000).

## ✨ Features

- **🔐 User Authentication**: Login and registration with secure password hashing (via `bcryptjs`) and session management.
- **📊 Nutrition Data Display**: Fetches and displays nutrition data using APIs and custom components.
- **📱 Responsive Design**: Fully responsive UI using Tailwind CSS.
- **🍪 Cookie Management**: Utilizes `js-cookie` for handling cookies and session persistence.
- **🗓️ Date Management**: `date-fns` is used for managing and displaying dates effectively.

## 📁 Project Structure

```plaintext
Nutrition_app/
├── package.json
├── package-lock.json
├── README.md
├── .env
├── src/
│   ├── app/
│   │   ├── (admin)/
│   │   │   ├── editMealItem/
│   │   │   ├── editMeals/
│   │   │   ├── editUser/
│   │   ├── (auth)/
│   │   │   ├── login/
│   │   │   ├── register/
│   │   │   └── signup/
│   │   ├── (website)/
│   │   │   ├── edit-meal/
│   │   │   ├── food-logs/
│   │   │   ├── payment/
│   │   │   ├── payment-cancel/
│   │   │   ├── payment-success/
│   │   │   └── profile/
│   │   ├── api/
│   │       ├── nutritionixApi.js
│   │       ├── login/
│   │       ├── logout/
│   │       ├── stripe/
│   │       └── user/
│   ├── components/
│   │   ├── CustomizeIngredients.js
│   │   ├── EditMealComponent.js
│   │   ├── admin_components/
│   │   ├── database_components/
│   │   │   ├── mealItem/
│   │   │   ├── meals/
│   │   │   └── user/
│   │   ├── profile_components/
│   │       ├── MealLog.js
│   ├── services/
│       ├── auth.js
│       ├── meals.js
│       ├── users.js
└── cypress/
    ├── e2e/
    ├── fixtures/
    └── support/
```
### 📑 Key Components

- **📝 package.json & package-lock.json**: Manage dependencies and scripts for the project.
- **⚙️ next.config.mjs**: Next.js configuration file.
- **📁 src/**: Contains the core application code.
  - **📂 app/**: Different pages and routing logic.
  - **📦 components/**: Reusable UI components.
  - **🔧 services/**: Utility services and data fetching.
- **🧪 cypress/**: Testing-related files including e2e and component tests.

Feel free to explore each directory to gain a better understanding of the project setup.

## 🗄️ Database Structure
The database consists of four primary tables and one join table:

1. **👤 Users**
2. **🍛 Meals**
3. **🍲 Meal Items**
4. **🛑 Roles**
5. **🔗 User Roles** (join table)

Below, we'll describe how these tables relate to one another, with the relationships defined by the 🔑 foreign keys.

### 📋 Tables Overview

#### 1. **👤 Users Table**

- **🔑 Primary Key**: `🆔 user_id`
- **Attributes**: 
  - `👤 username`: The name of the user.
  - `📧 email`: The unique email address of the user.
  - `🔒 password_hash`: The hashed password for the user's account.

#### 2. **🍛 Meals Table**

- **🔑 Primary Key**: `🆔 meal_id`
- **🔗 Foreign Key**: `🆔 user_id` → **references** `👤 users(user_id)`
- **Attributes**: 
  - `🔢 meal_number`: The meal number (e.g., 1 for breakfast, 2 for lunch).
  - `⏰ meal_time`: The time at which the meal was eaten.
  - `📅 log_date`: The date of the meal.
  - `🕒 createdAt`: The timestamp when the meal entry was created (automatically generated).

#### 3. **🍲 Meal Items Table**

- **🔑 Primary Key**: `🆔 meal_item_id`
- **🔗 Foreign Key**: `🆔 meal_id` → **references** `🍛 meals(meal_id)`
- **Attributes**: 
  - `🍽️ food_name`: The name of the food item.
  - `⚖️ food_quantity`: The quantity of the food item in grams.
  - `🔥 food_calories`: The number of calories in the food item.
  - `💪 food_protein`: The amount of protein in grams.
  - `🍞 food_carb`: The amount of carbohydrates in grams.
  - `🌾 food_fiber`: The amount of fiber in grams.

#### 4. **🛑 Roles Table**

- **🔑 Primary Key**: `🆔 role_id`
- **Attributes**: 
  - `📝 role_name`: The name of the role, such as 'User', 'VIP', or 'Admin'.

#### 5. **🔗 User Roles Table**

- **Composite Primary Key**: (`🆔 user_id`, `🆔 role_id`)
- **Foreign Keys**: 
  - `🆔 user_id` → **references** `👤 users(user_id)`
  - `🆔 role_id` → **references** `🛑 roles(role_id)`
- **Purpose**: This table establishes a **many-to-many** relationship between users and roles. A user can have multiple roles, and a role can be assigned to multiple users.

### 🔗 Relationships

#### 1. **👤 Users ➔ 🍛 Meals**

- **1️⃣ One-to-Many**: A `👤 user` can log multiple `🍛 meals`.
- Represented by: **`🆔 user_id`** in the `🍛 meals` table, which references the **primary key** of the `👤 users` table.

#### 2. **🍛 Meals ➔ 🍲 Meal Items**

- **1️⃣ One-to-Many**: A `🍛 meal` can have multiple `🍲 meal_items`.
- Represented by: **`🆔 meal_id`** in the `🍲 meal_items` table, which references the **primary key** of the `🍛 meals` table.

#### 3. **👤 Users ➔ 🛑 Roles (via 🔗 User Roles Table)**

- **🔄 Many-to-Many**: A `👤 user` can have multiple `🛑 roles` and each `🛑 role` can be assigned to multiple `👤 users`.
- Represented by the `🔗 user_roles` table, which references **`🆔 user_id`** and **`🆔 role_id`** from both tables.

### 🗺️ Diagram Representation

```
 👤 users                          🍛 meals                            🍲 meal_items
+------------------+       +--------------------+       +-------------------------+
| 🆔 user_id (PK)   |       | 🆔 meal_id (PK)    |       | 🆔 meal_item_id (PK)    |
| 👤 username       |<------| 🆔 user_id (FK)   |       | 🆔 meal_id (FK)         |
| 📧 email (UNIQUE) |       | 🔢 meal_number    |<------| 🍽️ food_name            |
| 🔒 password_hash  |       | ⏰ meal_time      |       | ⚖️ food_quantity        |
+------------------+       | 📅 log_date       |       | 🔥 food_calories        |
                       | 🕒 createdAt       |       | 💪 food_protein          |
                       +--------------------+       | 🍞 food_carb             |
                                                    | 🌾 food_fiber            |
                                                    +-------------------------+

                  🛑 roles                      🔗 user_roles
+---------------------+      +-------------------------------+
| 🆔 role_id (PK)     |      | 🆔 user_id (FK)               |
| 📝 role_name        |<---->| 🆔 role_id (FK)               |
+---------------------+      +-------------------------------+

```

- **🔑 Primary Keys** are marked as `(PK)`.
- **🔗 Foreign Keys** are marked as `(FK)`.
- The arrows (➔) indicate the relationships between the tables:
  - `🆔 user_id` in `🍛 meals` is a **foreign key** pointing to `🆔 user_id` in `👤 users`.
  - `🆔 meal_id` in `🍲 meal_items` is a **foreign key** pointing to `🆔 meal_id` in `🍛 meals`.
  - `🆔 user_id` and `🆔 role_id` in `🔗 user_roles` establish many-to-many relationships between `👤 users` and `🛑 roles`.

### 📊 Summary

- A **👤 user** can log multiple **🍛 meals** (e.g., 🍳 breakfast, 🥗 lunch).
- Each **🍛 meal** can consist of multiple **🍲 meal items** (e.g., different 🍔 foods eaten during that meal).
- Users can also have different **🛑 roles** (e.g., 'User', 'Admin') using the `🔗 user_roles` join table.
- The structure captures a **1️⃣ one-to-many** relationship between users and meals, a **one-to-many** relationship between meals and meal items, and a **many-to-many** relationship between users and roles.

## 🔑 Environment Variables

This project requires environment variables to function. Create a `.env` file at the root of your project with the following keys:

- `NEXT_PUBLIC_API_KEY`: Your API key for accessing nutrition data.
- `SUPABASE_URL`: URL for your Supabase project.
- `SUPABASE_ANON_KEY`: Public anon key for Supabase.
- `DATABASE_URL`: Connection string for Neon Database (if applicable).

Add additional environment variables as necessary based on your specific API setup.

## 📜 Scripts

- `npm run dev`: Runs the development server on [localhost:3000](http://localhost:3000).
- `npm run build`: Builds the project for production.
- `npm start`: Runs the production build.
- `npm run lint`: Lints the codebase using ESLint.

## 📦 Dependencies

**Core:**
- `next`: ^14.2.11
- `react` & `react-dom`: ^18 (React library)
- `tailwindcss`: ^3.4.1 (CSS framework)

**Data & APIs:**
- `@neondatabase/serverless`: ^0.9.5 (Neon Database integration)
- `axios`: ^1.7.7 (Promise-based HTTP client)

**Utilities:**
- `bcryptjs`: ^2.4.3 (Password hashing)
- `cookie`: ^0.6.0 (HTTP cookies)
- `js-cookie`: ^3.0.5 (Client-side cookie management)
- `date-fns`: ^4.1.0 (Date manipulation)

## 🛠️ Technologies Used

- **Next.js**: A React framework for server-rendered applications.
- **Tailwind CSS**: Utility-first CSS framework for styling.
- **Neon Database**: Serverless PostgreSQL database.
- **ESLint**: For consistent code quality and style.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to the creators of Next.js, Tailwind CSS, Neon, and any other libraries and APIs used.
- Special thanks to [Nutritionix] for the nutrition data API.
