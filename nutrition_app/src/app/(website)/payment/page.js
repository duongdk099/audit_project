'use client';
import { useState, useEffect } from 'react';
import Cookies from 'js-cookie'; // Import js-cookie for authentication
import { loadStripe } from '@stripe/stripe-js';

// Initialize Stripe.js with your publishable key
const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function PaymentPage() {
  const [loading, setLoading] = useState(true); // Loading state
  const [isAuthenticated, setIsAuthenticated] = useState(false); // Auth state
  const [checkoutLoading, setCheckoutLoading] = useState(false); // Payment processing state
  const [userName, setUserName] = useState(''); // User's name

  // useEffect to check authentication
  useEffect(() => {
    const authToken = Cookies.get('authToken'); // Check for authToken in cookies
    if (!authToken || authToken === '') {
      // If no auth token is found, redirect to login page
      window.location.href = '/login';
    } else {
      try {
        const user = JSON.parse(authToken);

        if (user?.user_id) {
          setIsAuthenticated(true); // User is authenticated
          setUserName(user.username || 'Guest'); // Set the user's name, default to "Guest" if not available
        } else {
          // Invalid token format, redirect to login
          window.location.href = '/login';
        }
      } catch (e) {
        // Handle token parsing errors
        console.error('Invalid auth token, redirecting to login...');
        window.location.href = '/login';
      } finally {
        setLoading(false); // Stop loading once auth process is completed
      }
    }
  }, []);

  const handleCheckout = async () => {
    setCheckoutLoading(true);
    const stripe = await stripePromise;

    try {
      const response = await fetch('/api/stripe/create-checkout-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const { sessionId } = await response.json();
      const { error } = await stripe.redirectToCheckout({ sessionId });

      if (error) {
        console.error('Error redirecting to checkout:', error);
        setCheckoutLoading(false);
      }
    } catch (err) {
      console.error('Error creating checkout session:', err);
      setCheckoutLoading(false);
    }
  };

  if (loading) return <div>Loading...</div>; // Show loading if still checking auth

  if (!isAuthenticated) return null; // Don't render the page if user is not authenticated

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-r from-blue-50 to-blue-100 p-4">
      <div className="bg-white rounded-lg shadow-lg p-8 max-w-sm w-full text-center">
        <h1 className="text-3xl font-semibold text-blue-700 mb-4">Welcome, {userName}!</h1>
        <h2 className="text-2xl font-semibold text-gray-800 mb-4">Complete Your Payment</h2>
        <p className="text-gray-600 mb-6">
          Purchase your <span className="font-bold">Sample Product</span> for only <span className="font-bold text-green-600">$5.00</span>
        </p>

        <button
          onClick={handleCheckout}
          disabled={checkoutLoading}
          className={`w-full py-3 px-4 rounded-lg text-white font-medium transition-colors 
                      ${checkoutLoading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600'}`}
        >
          {checkoutLoading ? 'Processing...' : 'Pay $5.00'}
        </button>

        <p className="text-sm text-gray-500 mt-6">
          You will be redirected to a secure payment page powered by Stripe.
        </p>
        <p className="text-xs text-gray-400 mt-2">
          Thank you for choosing our service, {userName}!
        </p>
      </div>
    </div>
  );
}
