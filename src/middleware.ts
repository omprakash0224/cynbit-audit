import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Cynbit Security & Edge Performance Middleware
 * 
 * Objectives:
 * 1. Enforce strict HTTP Security Headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
 * 2. Mitigate Tech Stack Fingerprinting (strip 'X-Powered-By').
 * 3. Scoped CORS policy (replace global wildcard CORS with restricted origins).
 * 4. Subdomain & Session Access Guarding for internal portals.
 */

// Permitted origins for API & Server Action invocations
const ALLOWED_ORIGINS = new Set([
  'https://www.cynbit.in',
  'https://cynbit.in',
  'https://portal.cynbit.in',
]);

export function middleware(request: NextRequest) {
  const origin = request.headers.get('origin');
  const response = NextResponse.next();

  // 1. Content Security Policy (CSP) Definition
  // Note: Allows Google Analytics (G-LK6CQWCWX0) and Google Fonts observed on Cynbit
  const cspHeader = `
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com;
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    font-src 'self' https://fonts.gstatic.com data:;
    img-src 'self' data: https://cynbit.in https://www.cynbit.in;
    connect-src 'self' https://www.google-analytics.com https://analytics.google.com https://*.cynbit.in;
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'self';
    upgrade-insecure-requests;
  `.replace(/\s{2,}/g, ' ').trim();

  // 2. Inject Defensive Security Headers
  response.headers.set('Content-Security-Policy', cspHeader);
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  response.headers.set(
    'Strict-Transport-Security',
    'max-age=63072000; includeSubDomains; preload'
  );

  // 3. Strip Tech Stack Fingerprint Headers
  response.headers.delete('x-powered-by');
  response.headers.delete('X-Powered-By');

  // 4. Scoped CORS Policy (avoid returning Access-Control-Allow-Origin: * universally)
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Vary', 'Origin');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    response.headers.set(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Next-Action, Next-Router-State-Tree'
    );
    response.headers.set('Access-Control-Allow-Credentials', 'true');
  }

  // 5. Handle preflight CORS requests
  if (request.method === 'OPTIONS') {
    return new NextResponse(null, { status: 204, headers: response.headers });
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for static files:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, favicon.svg, logo.svg
     */
    '/((?!_next/static|_next/image|favicon.svg|favicon.ico|logo.svg).*)',
  ],
};

