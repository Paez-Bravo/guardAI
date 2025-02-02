'use client';
// app/components/security/SecurityAnalysis.tsx
import React, { useState } from 'react';
import { AuthService } from '@/app/services/authService';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

interface AnalysisResult {
  url: string;
  risk_score: number;
  recommendations: string[];
  ai_analysis: {
    analysis: string;
    risk_summary: string;
    recommendations: string[];
  };
}

const SecurityAnalysis = () => {
  const [url, setUrl] = useState('');
  const [description, setDescription] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  const handleAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAnalyzing(true);
    setError('');
    setResult(null);

    try {
      const token = AuthService.getToken();
      const response = await fetch(`${AuthService['API_URL']}/api/v1/security/analyze-combined`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url, description })
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
        }
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Error en el análisis');
      }
      
      const data = await response.json();
      setResult(data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error en el análisis';
      setError(errorMessage);
      if (errorMessage.includes('Sesión expirada')) {
        // Redirigir al login después de un breve delay
        setTimeout(() => {
          window.location.href = '/login';
        }, 2000);
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-gray-900 bg-opacity-90 p-6 rounded-lg">
        <h2 className="text-2xl font-bold text-green-500 mb-4">Análisis de URL</h2>
        
        <form onSubmit={handleAnalysis} className="space-y-4">
          <div>
            <label htmlFor="url" className="block text-sm font-medium text-gray-300 mb-1">
              URL a Analizar
            </label>
            <input
              id="url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-white"
              required
              placeholder="https://ejemplo.com"
            />
          </div>

          <div>
            <label htmlFor="description" className="block text-sm font-medium text-gray-300 mb-1">
              Descripción (opcional)
            </label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-white"
              rows={3}
              placeholder="Añade contexto sobre la URL..."
            />
          </div>

          <button
            type="submit"
            disabled={isAnalyzing}
            className={`w-full py-2 px-4 bg-green-600 hover:bg-green-700 text-white rounded-md transition-colors
              ${isAnalyzing ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isAnalyzing ? 'Analizando...' : 'Analizar URL'}
          </button>
        </form>
      </div>

      {error && (
        <div className="bg-red-500 bg-opacity-10 border border-red-500 text-red-500 p-4 rounded-lg">
          {error}
        </div>
      )}

      {result && (
        <div className="bg-gray-900 bg-opacity-90 p-6 rounded-lg space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-bold text-white">Resultados del Análisis</h3>
            <div className={`px-3 py-1 rounded-full ${
              result.risk_score < 30 ? 'bg-green-500/20 text-green-500' :
              result.risk_score < 70 ? 'bg-yellow-500/20 text-yellow-500' :
              'bg-red-500/20 text-red-500'
            }`}>
              Riesgo: {result.risk_score}%
            </div>
          </div>

          <div className="space-y-4">
            {result.ai_analysis && (
              <div className="bg-gray-800 p-4 rounded-lg">
                <h4 className="font-semibold text-green-500 mb-2">Análisis IA</h4>
                <p className="text-gray-300">{result.ai_analysis.analysis}</p>
              </div>
            )}

            {result.recommendations && result.recommendations.length > 0 && (
              <div className="bg-gray-800 p-4 rounded-lg">
                <h4 className="font-semibold text-green-500 mb-2">Recomendaciones</h4>
                <ul className="list-disc list-inside space-y-1 text-gray-300">
                  {result.recommendations.map((rec, index) => (
                    <li key={index}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityAnalysis;
