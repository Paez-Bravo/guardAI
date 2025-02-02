from typing import List, Dict, Optional
from datetime import datetime, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from app.models.url_check import URLCheck
from app.models.user import User
from app.core.config import settings
from app.exceptions import UserLimitExceededError, ServiceError

logger = logging.getLogger(__name__)

class URLCheckService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_user_limits(self, user: User) -> bool:
        """
        Verifica si el usuario ha excedido su límite diario de verificaciones.
        """
        try:
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

            query = select(func.count(URLCheck.id)).where(
                URLCheck.user_id == user.id,
                URLCheck.checked_at >= today_start
            )

            result = await self.db.execute(query)
            count = result.scalar_one()

            limit_map = {
                'basic': settings.BASIC_USER_DAILY_LIMIT,
                'analyst': settings.ANALYST_USER_DAILY_LIMIT,
                'admin': settings.ADMIN_USER_DAILY_LIMIT
            }

            user_limit = limit_map.get(user.role, limit_map['basic'])

            if count >= user_limit:
                raise UserLimitExceededError(
                    f"Límite diario excedido para rol {user.role}: {count}/{user_limit}"
                )

            return True

        except UserLimitExceededError:
            raise
        except Exception as e:
            logger.error(f"Error verificando límites de usuario: {e}", exc_info=True)
            raise ServiceError(f"Error verificando límites: {str(e)}")

    async def log_url_check(
        self,
        user_id: int,
        url: str,
        result: Dict,
        description: Optional[str] = None
    ) -> URLCheck:
        """
        Registra una verificación de URL en la base de datos.
        """
        try:
            url_check = URLCheck(
                user_id=user_id,
                url=url,
                is_malicious=result.get('is_malicious', False),
                risk_score=float(result.get('risk_score', 0.0)),
                threats=result.get('threats', []),
                recommendations=result.get('recommendations', []),
                detailed_analysis=result.get('analysis_details'),
                description=description,
                source=result.get('source', 'otx'),
                status='completed'
            )

            self.db.add(url_check)
            await self.db.commit()
            await self.db.refresh(url_check)

            logger.info(f"URL check registrado: {url_check.id} para URL {url}")
            return url_check

        except Exception as e:
            logger.error(f"Error registrando verificación de URL: {e}", exc_info=True)
            await self.db.rollback()
            raise ServiceError(f"Error registrando verificación: {str(e)}")

    async def log_file_check(
        self,
        user_id: int,
        filename: str,
        result: Dict,
        description: Optional[str] = None
    ) -> URLCheck:
        """Registra un análisis de archivo en la base de datos."""
        try:
            url_check = URLCheck(
                user_id=user_id,
                url=f"file://{filename}",
                is_malicious=result.get('stats', {}).get('malicious', 0) > 0,
                risk_score=float(result.get('stats', {}).get('malicious', 0)) / 
                         max(sum(result.get('stats', {}).values()), 1) * 100,
                threats=[{
                    'type': 'malware',
                    'severity': 'high' if r.get('category') == 'malicious' else 'medium',
                    'description': r.get('result', 'Unknown threat'),
                    'source': r.get('engine', 'VirusTotal'),
                    'detected_at': datetime.now().isoformat()
                } for r in result.get('results', [])],
                recommendations=[
                    "Archivo detectado como malicioso - No ejecutar",
                    f"Detectado por {result.get('stats', {}).get('malicious', 0)} antivirus"
                ] if result.get('stats', {}).get('malicious', 0) > 0 else 
                ["No se detectaron amenazas en el archivo"],
                description=description,
                source='virustotal',
                status='completed'
            )
            
            self.db.add(url_check)
            await self.db.commit()
            await self.db.refresh(url_check)
            
            logger.info(f"Análisis de archivo registrado: {url_check.id} para archivo {filename}")
            return url_check

        except Exception as e:
            logger.error(f"Error registrando análisis de archivo: {e}", exc_info=True)
            await self.db.rollback()
            raise ServiceError(f"Error registrando análisis: {str(e)}")

    async def get_user_url_checks(
        self,
        user_id: int,
        skip: int = 0,
        limit: int = 10
    ) -> List[URLCheck]:
        """
        Obtiene el historial de verificaciones de URL de un usuario.
        """
        try:
            query = select(URLCheck).where(
                URLCheck.user_id == user_id
            ).order_by(
                URLCheck.checked_at.desc()
            ).offset(skip).limit(limit)

            result = await self.db.execute(query)
            return result.scalars().all()

        except Exception as e:
            logger.error(f"Error obteniendo historial de verificaciones: {e}", exc_info=True)
            raise ServiceError(f"Error obteniendo historial: {str(e)}")

    async def get_security_stats(self) -> Dict:
        """
        Obtiene estadísticas generales del sistema.
        """
        try:
            # Total de verificaciones
            total_query = select(func.count(URLCheck.id))
            total_result = await self.db.execute(total_query)
            total_checks = total_result.scalar_one()

            # Verificaciones maliciosas
            malicious_query = select(func.count(URLCheck.id)).where(
                URLCheck.is_malicious == True
            )
            malicious_result = await self.db.execute(malicious_query)
            malicious_checks = malicious_result.scalar_one()

            # Promedio de risk score
            avg_score_query = select(func.avg(URLCheck.risk_score))
            avg_score_result = await self.db.execute(avg_score_query)
            avg_risk_score = avg_score_result.scalar_one() or 0.0

            return {
                "total_checks": total_checks,
                "malicious_detected": malicious_checks,
                "average_risk_score": round(float(avg_risk_score), 2),
                "detection_rate": round(malicious_checks / total_checks * 100, 2) if total_checks > 0 else 0,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}", exc_info=True)
            raise ServiceError(f"Error obteniendo estadísticas: {str(e)}")
