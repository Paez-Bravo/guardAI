// app/services/authService.ts
import Cookies from 'js-cookie';

interface LoginCredentials {
  username: string;
  password: string;
}

interface AuthResponse {
  access_token: string;
  token_type: string;
}

export class AuthService {
  private static API_URL = 'http://143.47.41.101:8080';
  private static TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlciIsInJvbGUiOiJiYXNpYyIsImV4cCI6MTczODM0NDcwOX0.KIUn6991tV1Rc9FSkjmyTK1-kpKCjk_dEyoUBCip7KY";

  static async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      console.log('Attempting login with credentials:', credentials.username);
      
      const response = await fetch(`${this.API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentials),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Error en la autenticación');
      }

      const data = await response.json();
      // Para pruebas, seguimos usando el token hardcodeado
      console.log('Login successful');
      return {
        access_token: this.TOKEN,
        token_type: "bearer"
      };
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  }

  static async makeAuthRequest(endpoint: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${this.TOKEN}`);
    headers.set('Content-Type', 'application/json');

    try {
      console.log('Making request to:', `${this.API_URL}${endpoint}`);
      console.log('With headers:', Object.fromEntries(headers.entries()));
      
      const response = await fetch(`${this.API_URL}${endpoint}`, {
        ...options,
        headers,
        credentials: 'include'
      });

      console.log('Response status:', response.status);
      return response;
    } catch (error) {
      console.error('Network error:', error);
      throw error;
    }
  }

  static async getCurrentUser() {
    try {
      const response = await this.makeAuthRequest('/api/v1/auth/me');
      if (!response.ok) {
        if (response.status === 401) {
          return null;
        }
        throw new Error('Error obteniendo usuario');
      }
      return response.json();
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  }

  static getToken(): string {
    return this.TOKEN;
  }

  static isAuthenticated(): boolean {
    return true;  // Siempre autenticado para pruebas
  }

  static logout(): void {
    window.location.href = '/login';
  }
}
