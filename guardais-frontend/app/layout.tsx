// app/layout.tsx
import type { Metadata } from 'next'
import { AuthProvider } from './context/AuthContext'
import './globals.css'

export const metadata: Metadata = {
  title: 'GUARDAIS - Sistema de Análisis de Seguridad',
  description: 'Plataforma de análisis de seguridad y ciberseguridad',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="es">
      <body className="bg-black">
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  )
}
