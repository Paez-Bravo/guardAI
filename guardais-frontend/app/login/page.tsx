'use client';
// app/login/page.tsx
import LoginForm from '../components/auth/LoginForm';
import MatrixBackground from '../components/layout/MatrixBackground';

export default function LoginPage() {
  return (
    <div className="min-h-screen bg-black">
      <MatrixBackground />
      <LoginForm />
    </div>
  );
}
