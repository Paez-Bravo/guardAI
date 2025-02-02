from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class SafeBrowsingService:
    """Servicio para verificar URLs usando Google Safe Browsing API."""

    def __init__(self):
        self.api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
        self.base_url = "https://safebrowsing.googleapis.com/v4"
        self.client_id = "GuardAIS"
        self.client_version = "1.0.0"

    async def check_url(self, url: str) -> Dict:
        """
        Verifica una URL usando Google Safe Browsing.
        """
        try:
            async with aiohttp.ClientSession() as session:
                api_url = f"{self.base_url}/threatMatches:find?key={self.api_key}"
                
                payload = {
                    "client": {
                        "clientId": self.client_id,
                        "clientVersion": self.client_version
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }

                async with session.post(api_url, json=payload) as response:
                    if response.status != 200:
                        raise Exception(f"Error en Google Safe Browsing API: {response.status}")
                    
                    result = await response.json()
                    return self._process_results(url, result)

        except Exception as e:
            logger.error(f"Error verificando URL en Safe Browsing: {str(e)}")
            raise

    def _process_results(self, url: str, result: Dict) -> Dict:
        """
        Procesa los resultados de la API.
        """
        threats = result.get("matches", [])
        
        processed_threats = []
        for threat in threats:
            processed_threats.append({
                "type": threat.get("threatType"),
                "platform": threat.get("platformType"),
                "threat_entry_type": threat.get("threatEntryType"),
                "cache_duration": threat.get("cacheDuration", "300s")
            })

        return {
            "url": url,
            "is_malicious": bool(threats),
            "threats_found": len(threats),
            "threats": processed_threats,
            "risk_score": 100 if threats else 0,
            "checked_at": datetime.now().isoformat(),
            "recommendations": self._generate_recommendations(threats)
        }

    def _generate_recommendations(self, threats: List[Dict]) -> List[str]:
        """
        Genera recomendaciones basadas en las amenazas encontradas.
        """
        if not threats:
            return ["No se detectaron amenazas en Google Safe Browsing"]

        recommendations = []
        threat_types = set(threat.get("threatType") for threat in threats)

        if "MALWARE" in threat_types:
            recommendations.append("ALERTA: Se ha detectado malware en esta URL. No acceder al sitio.")

        if "SOCIAL_ENGINEERING" in threat_types:
            recommendations.append("PELIGRO: Esta URL está marcada como phishing o ingeniería social.")

        if "UNWANTED_SOFTWARE" in threat_types:
            recommendations.append("PRECAUCIÓN: Este sitio puede intentar instalar software no deseado.")

        if "POTENTIALLY_HARMFUL_APPLICATION" in threat_types:
            recommendations.append("ADVERTENCIA: Se han detectado aplicaciones potencialmente dañinas.")

        recommendations.append("Se recomienda evitar completamente el acceso a este sitio.")

        return recommendations
