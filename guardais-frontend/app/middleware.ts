// /app/middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  // Obtener token de la cookie
  const token = request.cookies.get('auth_token');

  // Definir rutas públicas que no requieren autenticación
  const publicPaths = ['/login'];
  const isPublicPath = publicPaths.includes(request.nextUrl.pathname);

  // Si no hay token y no es una ruta pública, redirigir a login
  if (!token && !isPublicPath) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Si hay token y está intentando acceder a login, redirigir al dashboard
  if (token && isPublicPath) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  // Si todo está bien, continuar con la solicitud
  return NextResponse.next();
}

// Configurar las rutas que deben ser protegidas
export const config = {
  matcher: [
    /*
     * Coincidir con todas las rutas excepto:
     * - api (rutas API)
     * - _next/static (archivos estáticos)
     * - _next/image (optimización de imágenes)
     * - favicon.ico
     * - public (archivos públicos)
     */
    '/((?!api|_next/static|_next/image|favicon.ico|public).*)',
  ],
};
