import { NextResponse } from 'next/server';

export function middleware(req) {
  const authToken = req.cookies.get('authToken');

  const { pathname } = req.nextUrl;

  // Allow access if authToken exists
  if (authToken) {
    return NextResponse.next();
  }

  // If no token and trying to access protected pages, redirect to login
  if (pathname.startsWith('/food-logs') || pathname.startsWith('/profile')) {
    return NextResponse.redirect(new URL('/login', req.url));
  }

  // Allow other routes to pass through
  return NextResponse.next();
}
export const config = {
  matcher: ['/food-logs/:path*', '/profile/:path*', '/admin/:path*'],
};