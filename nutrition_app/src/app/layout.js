'use client'; // Important to enable client-side functionality for logout
import './globals.css'; // Import global styles (Tailwind setup)
import Link from 'next/link';
import { useEffect, useState } from 'react'; // For managing login state
import { useRouter } from 'next/navigation'; // For redirecting after logout

export default function Layout({ children }) {
  const [isLoggedIn, setIsLoggedIn] = useState(false); // Track if the user is logged in
  const router = useRouter(); // Allows us to navigate programmatically

  // Check for authToken in cookies when component loads
  useEffect(() => {
    // Log the cookies to debug.........

    const authToken = document.cookie.split('; ').find(row => row.startsWith('authToken='));
    setIsLoggedIn(!!authToken); // Set login state based on the presence of authToken
  }, []);

  // Handle user logout
  const handleLogout = async () => {
    await fetch('/api/logout', {
      method: 'POST',
    });
    setIsLoggedIn(false); // Update the login state after logging out
    router.push('/login'); // Redirect to login page after logout
  };

  return (
    <html lang="en">
      <body>
        {/* Header with Navigation */}
        <header className="bg-green-500 text-white shadow-md">
          <div className="container mx-auto px-4 py-4 flex justify-between items-center">
            <Link href="/" className="text-2xl font-bold">NutriLife</Link>
            <nav>
              <ul className="flex space-x-4">
                <li>
                  <Link href="/" className="hover:text-green-200">Home</Link>
                </li>
                {isLoggedIn ? (
                  <>
                    <li>
                      <Link href="/food-logs" className="hover:text-green-200">Food Logs</Link>
                    </li>
                    <li>
                      <Link href="/profile" className="hover:text-green-200">Profile</Link>
                    </li>
                    <li>
                      <button onClick={handleLogout} className="hover:text-green-200">Logout</button>
                    </li>
                  </>
                ) : (
                  <li>
                    <Link href="/login" className="hover:text-green-200">Login</Link>
                  </li>
                )}
              </ul>
            </nav>
          </div>
        </header>

        {/* Main Content */}
        <main>{children}</main>

        {/* Footer */}
        <footer className="bg-gray-800 text-white py-8">
          <div className="container mx-auto text-center">
            <p>&copy; 2023 NutriLife. All rights reserved.</p>
          </div>
        </footer>
      </body>
    </html>
  );
}