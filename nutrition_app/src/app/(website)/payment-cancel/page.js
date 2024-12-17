// src/app/payment/page.js
'use client';
import { useState } from 'react';
import { loadStripe } from '@stripe/stripe-js';

// Initialize Stripe.js with your publishable key
const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY);

export default function PaymentPage() {
  const [loading, setLoading] = useState(false);

  const handleCheckout = async () => {
    setLoading(true);
    const stripe = await stripePromise;
    
    const response = await fetch('/api/stripe/create-checkout-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    const { sessionId } = await response.json();
    const { error } = await stripe.redirectToCheckout({ sessionId });
    
    if (error) {
      console.error(error);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 p-4">
      <div className="bg-white rounded-lg shadow-lg p-8 max-w-sm w-full text-center">
        <h2 className="text-2xl font-semibold text-gray-800 mb-4">Complete Your Payment</h2>
        <p className="text-gray-600 mb-6">Purchase a sample product for only <span className="font-bold">$5.00</span></p>
        
        <button
          onClick={handleCheckout}
          disabled={loading}
          className={`w-full py-3 px-4 rounded-lg text-white font-medium transition-colors 
                      ${loading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600'}`}
        >
          {loading ? 'Processing...' : 'Pay $5.00'}
        </button>
        
        <p className="text-xs text-gray-500 mt-4">
          You will be redirected to a secure payment page powered by Stripe.
        </p>
      </div>
    </div>
  );
}
