'use client';

import React from 'react';
import { Shield, MessageSquare, History, BarChart2, LucideIcon } from 'lucide-react';
import MatrixBackground from './MatrixBackground';

interface BaseLayoutProps {
  children: React.ReactNode;
}

interface NavItemProps {
  icon: LucideIcon;
  text: string;
}

const BaseLayout: React.FC<BaseLayoutProps> = ({ children }) => {
  return (
    <div className="min-h-screen bg-black text-gray-100">
      <MatrixBackground />
      
      {/* Sidebar */}
      <nav className="fixed top-0 left-0 h-full w-64 bg-gray-900 bg-opacity-90 p-4">
        <div className="flex items-center space-x-2 mb-8">
          <Shield className="w-8 h-8 text-green-500" />
          <h1 className="text-xl font-bold text-green-500">GUARDAIS</h1>
        </div>
        
        <div className="space-y-4">
          <NavItem icon={Shield} text="Análisis URLs" />
          <NavItem icon={MessageSquare} text="Chat Experto" />
          <NavItem icon={History} text="Historial" />
          <NavItem icon={BarChart2} text="Dashboard" />
        </div>
      </nav>
      
      {/* Main Content */}
      <main className="ml-64 p-8 min-h-screen bg-opacity-90 bg-gray-900">
        {children}
      </main>
    </div>
  );
};

const NavItem: React.FC<NavItemProps> = ({ icon: Icon, text }) => (
  <button className="flex items-center space-x-2 w-full p-2 rounded hover:bg-gray-800 transition-colors">
    <Icon className="w-5 h-5" />
    <span>{text}</span>
  </button>
);

export default BaseLayout;
