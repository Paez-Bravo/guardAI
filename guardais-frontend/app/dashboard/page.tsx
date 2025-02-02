'use client';
// app/dashboard/page.tsx
import DashboardLayout from '../components/layout/DashboardLayout';
import SecurityAnalysis from '../components/security/SecurityAnalysis';
import ExpertChat from '../components/chat/ExpertChat';

export default function DashboardPage() {
  return (
    <DashboardLayout>
      <SecurityAnalysis />
    </DashboardLayout>
  );
}
