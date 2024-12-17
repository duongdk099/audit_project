import { NextResponse } from 'next/server';
import { serialize } from 'cookie';

export async function POST(req) {
  const { username, password } = await req.json();

  // Dummy authentication (replace this with actual validation)
  if (username === 'test' && password === 'password') {
    const token = 'yourAuthToken';  // In a real-world app, generate a secure token.

    // Set the authToken cookie (without httpOnly to allow client access)
    const response = NextResponse.json({ message: 'Login successful!' });
    response.headers.set('Set-Cookie', serialize('authToken', token, {
      // Removed httpOnly to allow client-side access to the cookie
      secure: process.env.NODE_ENV !== 'development',
      maxAge: 60 * 60 * 24 * 7, // 1 week
      sameSite: 'strict',
      path: '/',
    }));

    return response;
  }

  return NextResponse.json({ message: 'Invalid credentials!' }, { status: 401 });
}