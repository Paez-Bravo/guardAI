from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class ThreatFoxService:
    """Servicio para verificar IoCs usando ThreatFox."""

    def __init__(self):
        self.api_key = settings.THREATFOX_API_KEY
        self.base_url = "https://threatfox-api.abuse.ch/api/v1"
        self.headers = {
            "API-KEY": self.api_key,
            "Accept": "application/json"
        }

    async def check_ioc(self, url: str) -> Dict:
        """
        Verifica si una URL está relacionada con IoCs conocidos.
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "query": "search_ioc",
                    "search_term": url
                }

                async with session.post(
                    self.base_url,
                    headers=self.headers,
                    json=payload
                ) as response:
                    if response.status != 200:
                        logger.error(f"Error en ThreatFox API: {response.status}")
                        return self._get_default_response(url)

                    result = await response.json()
                    return self._process_results(url, result)

        except Exception as e:
            logger.error(f"Error verificando IoC en ThreatFox: {str(e)}")
            return self._get_default_response(url)

    def _process_results(self, url: str, result: Dict) -> Dict:
        """
        Procesa los resultados de la API.
        """
        data = result.get("data", [])
        
        if not data or result.get("query_status") != "ok":
            return self._get_default_response(url)

        iocs = []
        malware_details = set()
        confidence_scores = []

        for ioc in data:
            ioc_details = {
                "type": ioc.get("ioc_type"),
                "threat_type": ioc.get("threat_type"),
                "malware": ioc.get("malware"),
                "confidence_level": ioc.get("confidence_level", 0),
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "tags": ioc.get("tags", [])
            }
            iocs.append(ioc_details)
            
            if ioc.get("malware_printable"):
                malware_details.add(ioc.get("malware_printable"))
            
            if ioc.get("confidence_level"):
                confidence_scores.append(ioc.get("confidence_level"))

        avg_confidence = (
            sum(confidence_scores) / len(confidence_scores)
            if confidence_scores else 0
        )

        return {
            "url": url,
            "is_malicious": bool(iocs),
            "iocs_found": len(iocs),
            "ioc_details": iocs,
            "malware_families": list(malware_details),
            "confidence_score": avg_confidence,
            "risk_score": self._calculate_risk_score(iocs),
            "checked_at": datetime.now().isoformat(),
            "recommendations": self._generate_recommendations(iocs)
        }

    def _calculate_risk_score(self, iocs: List[Dict]) -> float:
        """
        Calcula el nivel de riesgo basado en los IoCs encontrados.
        """
        if not iocs:
            return 0.0

        score = 0
        for ioc in iocs:
            # Base score por cada IoC
            score += 20
            
            # Ajuste por nivel de confianza
            confidence = ioc.get("confidence_level", 0)
            score += confidence * 0.3
            
            # Bonus por malware conocido
            if ioc.get("malware"):
                score += 10
            
            # Bonus por tags críticos
            critical_tags = {"apt", "ransomware", "botnet", "trojan"}
            ioc_tags = set(t.lower() for t in ioc.get("tags", []))
            if critical_tags & ioc_tags:
                score += 15

        return min(100, score)

    def _generate_recommendations(self, iocs: List[Dict]) -> List[str]:
        """
        Genera recomendaciones basadas en los IoCs encontrados.
        """
        if not iocs:
            return ["No se encontraron indicadores de compromiso en ThreatFox"]

        recommendations = []
        malware_types = set()
        threat_types = set()

        for ioc in iocs:
            if ioc.get("malware"):
                malware_types.add(ioc["malware"])
            if ioc.get("threat_type"):
                threat_types.add(ioc["threat_type"])

        if malware_types:
            recommendations.append(
                f"Se detectó relación con malware conocido: {', '.join(malware_types)}"
            )

        if threat_types:
            recommendations.append(
                f"Tipos de amenazas identificadas: {', '.join(threat_types)}"
            )

        recommendations.append(
            "Se recomienda realizar un análisis de seguridad adicional debido "
            "a la detección de indicadores de compromiso."
        )

        return recommendations

    def _get_default_response(self, url: str) -> Dict:
        """
        Respuesta por defecto cuando no hay resultados o hay error.
        """
        return {
            "url": url,
            "is_malicious": False,
            "iocs_found": 0,
            "ioc_details": [],
            "malware_families": [],
            "confidence_score": 0,
            "risk_score": 0,
            "checked_at": datetime.now().isoformat(),
            "recommendations": ["No se encontraron indicadores de compromiso en ThreatFox"]
        }
