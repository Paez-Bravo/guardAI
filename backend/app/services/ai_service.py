from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
from openai import AsyncOpenAI
from app.core.config import settings

logger = logging.getLogger(__name__)

class AIService:
    """Servicio para análisis de seguridad usando IA."""

    def __init__(self):
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL

        # Personalidad base del experto en ciberseguridad
        self.expert_prompt = """Eres un experto senior en ciberseguridad con más de 15 años de experiencia en:
- Análisis de amenazas y vulnerabilidades
- Normativas internacionales (GDPR, NIST, ISO27001)
- Metodologías de seguridad (OWASP, MITRE ATT&CK)
- Hardening de sistemas y redes
- Respuesta a incidentes
- Forense digital
- Gestión de riesgos

Proporciona respuestas:
- Detalladas y técnicamente precisas
- Basadas en estándares y mejores prácticas
- Con recomendaciones específicas y accionables
- Citando normativas relevantes cuando aplique
- Incluyendo consideraciones de cumplimiento
- Con ejemplos prácticos cuando sea apropiado

Mantén siempre un tono profesional pero accesible."""

    async def analyze_results(self, combined_results: Dict) -> Dict:
        """Analiza los resultados combinados de los servicios de seguridad."""
        try:
            analysis_prompt = f"""Analiza los siguientes resultados de seguridad y proporciona:
1. Un resumen ejecutivo del nivel de riesgo
2. Detalles técnicos relevantes
3. Recomendaciones específicas
4. Consideraciones de cumplimiento normativo
5. Pasos de mitigación si se detectan amenazas

Resultados: {combined_results}"""

            messages = [
                {"role": "system", "content": self.expert_prompt},
                {"role": "user", "content": analysis_prompt}
            ]

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7
            )

            analysis = response.choices[0].message.content

            return {
                "analysis": analysis,
                "risk_summary": self._extract_risk_summary(analysis),
                "recommendations": self._extract_recommendations(analysis),
                "compliance_notes": self._extract_compliance_notes(analysis),
                "technical_details": self._extract_technical_details(analysis)
            }

        except Exception as e:
            logger.error(f"Error en análisis de IA: {str(e)}")
            raise

    async def get_expert_response(self, user_query: str, context: Optional[Dict] = None) -> str:
        """Proporciona respuestas expertas a consultas de seguridad."""
        try:
            expert_query = f"""Consulta de seguridad: {user_query}

Contexto adicional (si existe):
{context if context else 'No hay contexto adicional proporcionado'}

Proporciona una respuesta que:
1. Aborde directamente la consulta
2. Incluya consideraciones de seguridad relevantes
3. Cite normativas aplicables
4. Ofrezca recomendaciones prácticas
5. Considere mejores prácticas actuales"""

            messages = [
                {"role": "system", "content": self.expert_prompt},
                {"role": "user", "content": expert_query}
            ]

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Error en respuesta experta: {str(e)}")
            raise

    def _extract_risk_summary(self, analysis: str) -> str:
        """Extrae el resumen de riesgo del análisis."""
        # Implementar extracción inteligente del resumen
        return analysis.split('\n')[0] if analysis else ""

    def _extract_recommendations(self, analysis: str) -> List[str]:
        """Extrae las recomendaciones del análisis."""
        # Implementar extracción de recomendaciones
        return [line.strip() for line in analysis.split('\n') 
                if line.strip().startswith(('-', '•', '*'))]

    def _extract_compliance_notes(self, analysis: str) -> List[str]:
        """Extrae notas de cumplimiento del análisis."""
        # Implementar extracción de notas de cumplimiento
        return []

    def _extract_technical_details(self, analysis: str) -> Dict:
        """Extrae detalles técnicos del análisis."""
        # Implementar extracción de detalles técnicos
        return {}
