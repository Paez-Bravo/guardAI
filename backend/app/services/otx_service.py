from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse
import validators
import logging
import asyncio
import json
from OTXv2 import OTXv2, IndicatorTypes
from app.core.config import settings
from cachetools import TTLCache

logger = logging.getLogger(__name__)

class OTXService:
    """
    Servicio para verificar URLs utilizando AlienVault OTX.
    """

    def __init__(self):
        """Inicializa el servicio OTX con configuración y caché."""
        self.otx = OTXv2(settings.OTX_API_KEY, server='https://otx.alienvault.com')
        self.cache = TTLCache(maxsize=1000, ttl=settings.CACHE_TTL)
        self.rate_limits = {
            'basic': {'calls': settings.BASIC_USER_DAILY_LIMIT, 'period': 86400},
            'analyst': {'calls': settings.ANALYST_USER_DAILY_LIMIT, 'period': 86400},
            'admin': {'calls': settings.ADMIN_USER_DAILY_LIMIT, 'period': 86400}
        }
        self.call_history = {}
        self.max_retries = 3
        self.retry_delay = 1

    def _check_rate_limit(self, user_role: str) -> bool:
        """Verifica si se ha excedido el rate limit para el rol."""
        try:
            now = datetime.now()
            limits = self.rate_limits.get(user_role, self.rate_limits['basic'])
            period_start = now - timedelta(seconds=limits['period'])

            if user_role not in self.call_history:
                self.call_history[user_role] = []

            # Limpiar historial antiguo y verificar límites
            self.call_history[user_role] = [
                call_time for call_time in self.call_history[user_role]
                if call_time > period_start
            ]

            if len(self.call_history[user_role]) >= limits['calls']:
                logger.warning(f"Rate limit excedido para rol {user_role}")
                return False

            self.call_history[user_role].append(now)
            return True

        except Exception as e:
            logger.error(f"Error en rate limit: {e}")
            return False

    async def check_url(self, url: str, user_role: str = 'basic') -> Dict:
        """
        Verifica una URL utilizando AlienVault OTX.
        Incluye manejo de errores, reintentos y caché.
        """
        if not validators.url(url):
            logger.error(f"URL inválida: {url}")
            raise ValueError(f"Formato de URL no válido: {url}")

        if not self._check_rate_limit(user_role):
            logger.warning(f"Rate limit excedido para rol {user_role}")
            raise Exception("Rate limit exceeded for your role")

        cache_key = f"{url}:{user_role}"
        if cache_key in self.cache:
            logger.info(f"Retornando resultado cacheado para URL: {url}")
            return self.cache[cache_key]

        domain = self._extract_domain(url)
        logger.info(f"Analizando dominio: {domain}")

        for attempt in range(self.max_retries):
            try:
                results = self.otx.get_indicator_details_full(
                    IndicatorTypes.DOMAIN,
                    domain
                )

                threats = self._parse_threats(results)
                malware_data = self._check_malware(results)
                risk_score = self._calculate_risk_score(threats, malware_data)
                recommendations = self._generate_recommendations(risk_score, threats, malware_data)

                response = {
                    'url': url,
                    'is_malicious': risk_score > 70,
                    'risk_score': float(risk_score),
                    'threats': [self._serialize_threat(t) for t in threats],
                    'checked_at': datetime.now().isoformat(),
                    'recommendations': recommendations
                }

                self.cache[cache_key] = response
                return response

            except Exception as e:
                logger.warning(f"Intento {attempt + 1}/{self.max_retries} fallido: {str(e)}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                else:
                    raise Exception(f"Error al verificar URL después de {self.max_retries} intentos: {str(e)}")

    def _serialize_threat(self, threat: Dict) -> Dict:
        """Serializa una amenaza para asegurar compatibilidad JSON."""
        return {
            'type': threat['type'],
            'severity': threat['severity'],
            'description': threat['description'],
            'source': threat.get('source', "AlienVault OTX"),
            'detected_at': datetime.now().isoformat()
        }

    def _extract_domain(self, url: str) -> str:
        """Extrae el dominio de una URL de forma segura."""
        try:
            parsed_url = urlparse(url)
            return parsed_url.netloc or parsed_url.path
        except Exception as e:
            logger.error(f"Error extrayendo dominio de {url}: {e}")
            raise ValueError(f"Error procesando URL: {str(e)}")

    def _categorize_threat(self, pulse: Dict[str, Any]) -> str:
        """Categoriza el tipo de amenaza basado en tags y contenido."""
        try:
            if not isinstance(pulse, dict):
                return 'unknown'

            tags = set(t.lower() for t in pulse.get('tags', []) if isinstance(t, str))

            categories = {
                'phishing': {'phishing', 'scam', 'fraud'},
                'malware': {'malware', 'ransomware', 'spyware', 'botnet'},
                'ssl_issues': {'ssl', 'certificate', 'mitm'},
                'spam': {'spam', 'unwanted'},
                'exploit': {'exploit', 'vulnerability', 'cve'},
                'c2': {'c2', 'command-and-control', 'apt'}
            }

            for category, keywords in categories.items():
                if keywords & tags:
                    return category

            return 'unknown'
        except Exception as e:
            logger.error(f"Error categorizando amenaza: {str(e)}")
            return 'unknown'

    def _determine_severity(self, pulse: Dict[str, Any]) -> str:
        """Determina la severidad de una amenaza."""
        try:
            if pulse.get('malicious', False):
                return 'high'

            confidence = pulse.get('confidence', 0)
            if confidence > 70:
                return 'high'

            indicators = pulse.get('indicators', [])
            if isinstance(indicators, list) and len(indicators) > 5:
                return 'high'

            return 'medium' if confidence > 40 else 'low'

        except Exception as e:
            logger.error(f"Error determinando severidad: {str(e)}")
            return 'low'
    def _parse_threats(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parsea las amenazas de los resultados de OTX.
        """
        threats = []
        try:
            if not isinstance(results, dict):
                logger.warning(f"Formato de resultados inesperado: {type(results)}")
                return threats

            pulse_info = results.get('pulse_info', {})
            pulses = pulse_info.get('pulses', [])

            for pulse in pulses:
                if not isinstance(pulse, dict):
                    continue
                try:
                    threat_type = self._categorize_threat(pulse)
                    severity = self._determine_severity(pulse)
                    description = pulse.get('description', f"Amenaza detectada de tipo {threat_type}")

                    threat = {
                        'type': threat_type,
                        'severity': severity,
                        'description': description,
                        'source': "AlienVault OTX",
                        'detected_at': datetime.now().isoformat()
                    }
                    threats.append(threat)
                except Exception as e:
                    logger.error(f"Error analizando pulso: {str(e)}")
                    continue
        except Exception as e:
            logger.error(f"Error analizando amenazas: {str(e)}")
        return threats

    def _check_malware(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analiza datos específicos de malware."""
        malware_data = {
            'detected': False,
            'types': [],
            'families': [],
            'confidence': 0
        }

        try:
            malware = results.get('malware', [])
            if isinstance(malware, list):
                malware_data['detected'] = bool(malware)
                malware_data['types'] = [m.get('type') for m in malware if isinstance(m, dict) and 'type' in m]
                malware_data['families'] = [m.get('family') for m in malware if isinstance(m, dict) and 'family' in m]
                confidences = [m.get('confidence', 0) for m in malware if isinstance(m, dict)]
                malware_data['confidence'] = max(confidences) if confidences else 0
        except Exception as e:
            logger.error(f"Error analizando malware: {str(e)}")
        return malware_data

    def _calculate_risk_score(self, threats: List[Dict[str, Any]], malware_data: Dict[str, Any]) -> int:
        """Calcula el puntaje de riesgo basado en las amenazas detectadas."""
        try:
            score = 0
            severity_scores = {'high': 25, 'medium': 15, 'low': 5}
            
            # Puntuación basada en amenazas
            score += sum(severity_scores.get(threat['severity'], 0) for threat in threats)

            # Puntuación basada en malware
            if malware_data.get('detected', False):
                score += 30
                confidence = malware_data.get('confidence', 0)
                score += min(20, confidence // 5)

            # Puntuación por tipos únicos de amenazas
            unique_threat_types = len(set(threat['type'] for threat in threats))
            score += unique_threat_types * 5

            return min(100, max(0, score))
        except Exception as e:
            logger.error(f"Error calculando risk score: {str(e)}")
            return 0

    def _generate_recommendations(self, risk_score: float, threats: List[Dict[str, Any]], malware_data: Dict[str, Any]) -> List[str]:
        """Genera recomendaciones basadas en el análisis de seguridad."""
        recommendations = []
        try:
            # Recomendaciones basadas en el nivel de riesgo
            if risk_score > 70:
                recommendations.append("ALERTA CRÍTICA: Evitar acceder a esta URL - Alto riesgo detectado")
            elif risk_score > 40:
                recommendations.append("PRECAUCIÓN: Riesgo moderado detectado - Se recomienda verificación adicional")

            # Recomendaciones específicas por tipo de amenaza
            threat_types = set(threat['type'] for threat in threats)

            if 'phishing' in threat_types:
                recommendations.append("Posible sitio de phishing - No ingresar datos sensibles")
            if 'malware' in threat_types or malware_data.get('detected', False):
                recommendations.append("Detección de malware - Riesgo de infección")
            if 'ssl_issues' in threat_types:
                recommendations.append("Problemas con certificado SSL - Conexión no segura")
            if 'exploit' in threat_types:
                recommendations.append("Vulnerabilidades detectadas - Actualizar sistemas antes de acceder")
            if 'c2' in threat_types:
                recommendations.append("Posible servidor de comando y control - Bloquear acceso")

            if not recommendations:
                recommendations.append("No se detectaron amenazas significativas - Proceder con precaución normal")

            return recommendations

        except Exception as e:
            logger.error(f"Error generando recomendaciones: {str(e)}")
            return ["Error al generar recomendaciones - Proceder con máxima precaución"]
