from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp
import logging
import hashlib
import asyncio
import base64
from app.core.config import settings

logger = logging.getLogger(__name__)

class VirusTotalService:
    """Servicio para análisis usando VirusTotal API."""

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }
        self.max_retries = 3
        self.retry_delay = 1

    async def analyze_url(self, url: str) -> Dict:
        """Analiza una URL usando VirusTotal."""
        try:
            async with aiohttp.ClientSession() as session:
                # Crear identificador base64 de la URL
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                analysis_url = f"{self.base_url}/urls/{url_id}"

                # Intentar obtener análisis existente
                async with session.get(analysis_url, headers=self.headers) as response:
                    if response.status == 200:
                        return self._parse_url_analysis(await response.json())

                # Si no existe, enviar para análisis
                data = aiohttp.FormData()
                data.add_field("url", url)
                
                async with session.post(f"{self.base_url}/urls", headers=self.headers, data=data) as response:
                    if response.status not in [200, 201]:
                        raise Exception(f"Error al enviar URL a VirusTotal: {response.status}")
                    
                    # Esperar un poco para el análisis
                    await asyncio.sleep(3)
                    
                    # Obtener resultados
                    return await self._get_url_analysis(url_id)

        except Exception as e:
            logger.error(f"Error analizando URL en VirusTotal: {str(e)}")
            raise

    async def analyze_file(self, file_content: bytes, filename: str) -> Dict:
        """Analiza un archivo usando VirusTotal."""
        try:
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            # Intentar obtener análisis existente
            try:
                return await self._get_file_analysis(file_hash)
            except:
                # Si no existe, subir el archivo
                return await self._upload_and_analyze_file(file_content, filename)

        except Exception as e:
            logger.error(f"Error analizando archivo en VirusTotal: {str(e)}")
            raise

    async def _get_url_analysis(self, url_id: str) -> Dict:
        """Obtiene los resultados del análisis de una URL."""
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"{self.base_url}/urls/{url_id}"
                    
                    async with session.get(url, headers=self.headers) as response:
                        if response.status == 200:
                            result = await response.json()
                            return self._parse_url_analysis(result)
                        
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                        else:
                            raise Exception(f"Error obteniendo análisis: {response.status}")

            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise

    async def _upload_and_analyze_file(self, file_content: bytes, filename: str) -> Dict:
        """Sube y analiza un archivo en VirusTotal."""
        try:
            async with aiohttp.ClientSession() as session:
                # Obtener URL para subida
                async with session.get(f"{self.base_url}/files/upload_url", headers=self.headers) as response:
                    if response.status != 200:
                        raise Exception("Error obteniendo URL de subida")
                    
                    upload_url = (await response.json()).get("data")

                # Subir archivo
                form = aiohttp.FormData()
                form.add_field('file', file_content, filename=filename)
                
                async with session.post(upload_url, headers=self.headers, data=form) as response:
                    if response.status not in [200, 201]:
                        raise Exception("Error subiendo archivo")
                    
                    result = await response.json()
                    analysis_id = result.get("data", {}).get("id")
                    
                    if not analysis_id:
                        raise Exception("No se pudo obtener ID de análisis")

                    await asyncio.sleep(3)  # Esperar análisis inicial
                    return await self._get_file_analysis(analysis_id)

        except Exception as e:
            logger.error(f"Error en subida y análisis de archivo: {str(e)}")
            raise

    async def _get_file_analysis(self, file_hash: str) -> Dict:
        """Obtiene los resultados del análisis de un archivo por su hash."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/files/{file_hash}"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 404:
                        raise FileNotFoundError("Archivo no encontrado en VirusTotal")
                    
                    if response.status != 200:
                        raise Exception(f"Error al obtener análisis: {response.status}")
                    
                    return self._parse_file_analysis(await response.json())

        except Exception as e:
            logger.error(f"Error obteniendo análisis de archivo: {str(e)}")
            raise

    def _parse_url_analysis(self, result: Dict) -> Dict:
        """Parsea los resultados del análisis de URL."""
        try:
            attributes = result.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            return {
                "stats": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0)
                },
                "scan_date": attributes.get("last_analysis_date"),
                "results": [
                    {
                        "engine": engine,
                        "category": data.get("category", "unknown"),
                        "result": data.get("result", "unknown"),
                        "method": data.get("method", "unknown")
                    }
                    for engine, data in results.items()
                    if data.get("category") in ["malicious", "suspicious"]
                ],
                "reputation": attributes.get("reputation", 0),
                "total_votes": {
                    "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                }
            }

        except Exception as e:
            logger.error(f"Error parseando resultados: {str(e)}")
            raise

    def _parse_file_analysis(self, result: Dict) -> Dict:
        """Parsea los resultados del análisis de archivo."""
        try:
            attributes = result.get("data", {}).get("attributes", {})
            
            return {
                "sha256": attributes.get("sha256"),
                "md5": attributes.get("md5"),
                "size": attributes.get("size"),
                "type": attributes.get("type_description", "unknown"),
                "first_seen": attributes.get("first_submission_date"),
                "last_seen": attributes.get("last_analysis_date"),
                "stats": attributes.get("last_analysis_stats", {
                    "malicious": 0,
                    "suspicious": 0,
                    "clean": 0,
                    "undetected": 0
                }),
                "results": [
                    {
                        "engine": engine,
                        "category": data.get("category", "unknown"),
                        "result": data.get("result", "unknown")
                    }
                    for engine, data in attributes.get("last_analysis_results", {}).items()
                    if data.get("category") in ["malicious", "suspicious"]
                ],
                "tags": attributes.get("tags", []),
                "reputation": attributes.get("reputation", 0)
            }

        except Exception as e:
            logger.error(f"Error parseando resultados de archivo: {str(e)}")
            raise
