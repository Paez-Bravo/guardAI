'use client';
// app/components/chat/ExpertChat.tsx
import React, { useState, useRef, useEffect } from 'react';
import { Send, Loader, AlertCircle } from 'lucide-react';
import { AuthService } from '@/app/services/authService';

interface Message {
  role: 'user' | 'assistant' | 'error';
  content: string;
  timestamp: Date;
}

const ExpertChat = () => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage = input;
    setInput('');
    setError(null);
    setMessages(prev => [...prev, {
      role: 'user',
      content: userMessage,
      timestamp: new Date()
    }]);

    setIsLoading(true);

    try {
      console.log('Sending request to expert chat...');
      const response = await AuthService.makeAuthRequest('/api/v1/security/expert-chat', {
        method: 'POST',
        body: JSON.stringify({
          query: userMessage,
          context: { messages: messages.filter(m => m.role !== 'error') }
        })
      });

      console.log('Response received:', response.status);
      
      if (!response.ok) {
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.response,
        timestamp: new Date()
      }]);
    } catch (error) {
      console.error('Chat error:', error);
      const errorMessage = error instanceof Error 
        ? error.message 
        : 'Error de conexión. Por favor, verifica tu conexión e intenta de nuevo.';
      
      setError(errorMessage);
      setMessages(prev => [...prev, {
        role: 'error',
        content: errorMessage,
        timestamp: new Date()
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {error && (
          <div className="flex items-center space-x-2 bg-red-500 bg-opacity-10 border border-red-500 text-red-500 p-4 rounded">
            <AlertCircle className="h-5 w-5" />
            <span>{error}</span>
          </div>
        )}
        {messages.map((message, index) => (
          <div
            key={index}
            className={`p-4 rounded-lg ${
              message.role === 'user' 
                ? 'bg-green-900 bg-opacity-20 ml-4'
                : message.role === 'error'
                ? 'bg-red-900 bg-opacity-20'
                : 'bg-gray-800 mr-4'
            }`}
          >
            <div className="text-sm text-gray-400 mb-2">
              {message.role === 'user' ? 'Tú' : message.role === 'error' ? 'Error' : 'Experto IA'}
            </div>
            <div className="text-gray-100 whitespace-pre-wrap">
              {message.content}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} className="p-4 border-t border-gray-800">
        <div className="flex space-x-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={isLoading ? 'Esperando respuesta...' : 'Escribe tu consulta...'}
            disabled={isLoading}
            className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-md focus:outline-none focus:ring-2 focus:ring-green-500 text-white"
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className={`p-2 rounded-md ${
              isLoading || !input.trim()
                ? 'bg-gray-700 text-gray-400'
                : 'bg-green-600 hover:bg-green-700 text-white'
            } transition-colors`}
          >
            {isLoading ? (
              <Loader className="h-5 w-5 animate-spin" />
            ) : (
              <Send className="h-5 w-5" />
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default ExpertChat;
