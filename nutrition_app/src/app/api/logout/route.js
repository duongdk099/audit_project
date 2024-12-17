import { serialize } from 'cookie';
import { NextResponse } from 'next/server';

export async function POST() {
  const response = NextResponse.json({ message: 'Logged out successfully!' });

  // Clear the authToken cookie by setting it to expire immediately
  response.headers.set('Set-Cookie', serialize('authToken', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    maxAge: -1, // Expire the cookie
    path: '/',
  }));

  return response;
}