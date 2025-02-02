'use client';
// app/page.tsx
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from './context/AuthContext';
import MatrixBackground from './components/layout/MatrixBackground';

export default function Home() {
  const router = useRouter();
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    // Si no está autenticado, redirigir a login
    if (!isAuthenticated) {
      router.push('/login');
    } else {
      router.push('/dashboard');
    }
  }, [isAuthenticated, router]);

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center">
      <MatrixBackground />
      <div className="text-center z-10">
        <h1 className="text-4xl font-bold text-green-500 mb-4">GUARDAIS</h1>
        <p className="text-lg text-green-300">Cargando...</p>
      </div>
    </div>
  );
}
