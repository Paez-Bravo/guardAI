'use client';  
// app/components/layout/DashboardLayout.tsx  
import React from 'react';  
import { useAuth } from '@/app/context/AuthContext';  
import { Shield, LogOut } from 'lucide-react';  
import ExpertChat from '../chat/ExpertChat';  
import MatrixBackground from './MatrixBackground';  

interface DashboardLayoutProps {  
  children: React.ReactNode;  
}  

const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {  
  const { logout, user } = useAuth();  

  return (  
    <div className="min-h-screen bg-black text-white flex">  
      <MatrixBackground />  
      
      {/* Sidebar */}  
      <aside className="w-64 bg-gray-900 bg-opacity-90 min-h-screen p-4 flex flex-col relative z-10">  
        <div className="flex items-center space-x-2 mb-8">  
          <Shield className="h-8 w-8 text-green-500" />  
          <span className="text-xl font-bold text-green-500">GUARDAIS</span>  
        </div>  

        <nav className="flex-1">  
          <div className="space-y-4">  
            {/* Menú de navegación aquí */}  
          </div>  
        </nav>  

        <div className="pt-4 border-t border-gray-800">  
          <div className="flex items-center justify-between">  
            <div className="text-sm">  
              <p className="text-gray-400">Usuario</p>  
              <p className="text-green-500">{user?.username}</p>  
            </div>  
            <button   
              onClick={logout}  
              className="p-2 hover:bg-gray-800 rounded-full transition-colors"  
              title="Cerrar sesión"  
            >  
              <LogOut className="h-5 w-5 text-gray-400 hover:text-red-500" />  
            </button>  
          </div>  
        </div>  
      </aside>  

      {/* Main Content Area with Chat */}  
      <div className="flex-1 flex relative z-10">  
        {/* Main Content */}  
        <main className="flex-1 p-8 overflow-auto bg-gray-900 bg-opacity-90">  
          {children}  
        </main>  

        {/* Chat Panel */}  
        <aside className="w-96 bg-gray-900 bg-opacity-90 border-l border-gray-800 p-4 flex flex-col">  
          <h2 className="text-xl font-bold text-green-500 mb-4">  
            Chat con Experto IA  
          </h2>  
          <div className="flex-1">  
            <ExpertChat />  
          </div>  
        </aside>  
      </div>  
    </div>  
  );  
};  

export default DashboardLayout;
