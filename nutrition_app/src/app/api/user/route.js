import { NextResponse } from 'next/server';

const users = {
  testUser: {
    name: 'John Doe',
    email: 'john.doe@example.com',
    meals: [
      { id: 1, type: 'recipe', name: 'Delicious Salad Bowl', quantity: 1, unit: 'serving' },
      { id: 2, type: 'manual', name: 'Chicken Breast', quantity: 150, unit: 'grams' }
    ],
    nutrition: {
      calories: 2000,
      protein: 100,
      carbs: 300,
      fiber: 25,
      fat: 60,
    },
  },
};

// API Route to return user data based on token
export async function GET(req) {
  const authToken = req.cookies.get('authToken');

  console.log('Received Auth Token:', authToken);  // Debug log

  if (authToken === 'yourAuthToken') {  // Replace this with actual validation logic
    const user = users.testUser;
    console.log('Hi');
    
    return NextResponse.json(user);
  }

  return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
}