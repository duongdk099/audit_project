'use client';
import { useState, useEffect } from 'react';
import { useProfileData } from '@/components/profile_components/useProfileData'; // Custom hook for fetching data
import ProfileTable from '@/components/profile_components/ProfileTable'; // Profile UI component
import Cookies from 'js-cookie'; // Import js-cookie to manage cookies

export default function ProfilePage() {
  const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
  const [sortOption, setSortOption] = useState('meal_number'); // Default sorting option
  const [loading, setLoading] = useState(true); // State to track loading status
  const [isAuthenticated, setIsAuthenticated] = useState(false); // Track if user is authenticated

  // useEffect to check authentication
  useEffect(() => {
    const authToken = Cookies.get('authToken'); // Check if authToken exists
    if (!authToken || authToken === '') {
      // If no auth token is found, redirect to login page
      window.location.href = '/login';
    } else {
      try {
        const user = JSON.parse(authToken);

        if (user?.user_id) {
          setIsAuthenticated(true); // User is authenticated
        } else {
          // Invalid token format, redirect to login
          window.location.href = '/login';
        }
      } catch (e) {
        // If parsing fails, redirect to login
        console.error('Invalid auth token, redirecting to login...');
        window.location.href = '/login';
      } finally {
        setLoading(false); // Stop loading once auth process is completed
      }
    }
  }, []);

  // Use custom hook to fetch profile data if user is authenticated
  const { meals, error } = useProfileData(selectedDate, sortOption);

  const handleDateChange = (event) => {
    setSelectedDate(event.target.value);
  };

  const handleSortChange = (event) => {
    setSortOption(event.target.value);
  };

  // If the page is still checking for auth, show loading
  if (loading) return <div>Loading...</div>;

  // Render only if user is authenticated
  if (!isAuthenticated) return null;

  if (error) return <div>{error}</div>;

  return (
    <section className="py-12 bg-gray-100">
      <div className="container mx-auto px-4">
        <h1 className="text-3xl font-bold text-center mb-8">Your Profile</h1>

        {/* Date Picker for choosing which day's log to display */}
        <div className="text-center mb-8">
          <label className="text-lg mr-2">Choose a Date:</label>
          <input
            type="date"
            value={selectedDate}
            onChange={handleDateChange}
            className="p-2 border rounded"
          />
        </div>

        {/* Dropdown to select sort option */}
        <div className="text-center mb-8">
          <label className="text-lg mr-2">Sort by:</label>
          <select value={sortOption} onChange={handleSortChange} className="p-2 border rounded">
            <option value="meal_number">Meal Number</option>
            <option value="meal_time">Meal Time</option>
          </select>
        </div>

        {/* Use ProfileTable component to display the UI */}
        <ProfileTable meals={meals} />
      </div>
    </section>
  );
}
