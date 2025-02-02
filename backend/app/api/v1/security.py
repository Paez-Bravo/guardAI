from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Optional
import logging
from datetime import datetime
import asyncio

from app.services.safebrowsing_service import SafeBrowsingService
from app.services.threatfox_service import ThreatFoxService
from app.services.ai_service import AIService
from app.core.database import get_session
from app.models.user import User
from app.api.v1.auth import get_current_active_user
from app.schemas.security import (
    URLCheckRequest,
    URLCheckResponse,
    FileAnalysisResponse,
    CombinedAnalysisResponse,
    ExpertChatRequest,
    ExpertChatResponse,
    AIAnalysis
)
from app.services.otx_service import OTXService
from app.services.virustotal_service import VirusTotalService
from app.services.url_check_service import URLCheckService
from app.exceptions import ServiceError, InvalidURLError
from app.core.config import settings

logger = logging.getLogger("security_router")

router = APIRouter(prefix="/security", tags=["security"])

# Servicios
def get_otx_service() -> OTXService:
    """Obtiene una instancia del servicio OTX."""
    return OTXService()

def get_virustotal_service() -> VirusTotalService:
    """Obtiene una instancia del servicio VirusTotal."""
    return VirusTotalService()

def get_safebrowsing_service() -> SafeBrowsingService:
    """Obtiene una instancia del servicio Google Safe Browsing."""
    return SafeBrowsingService()

def get_threatfox_service() -> ThreatFoxService:
    """Obtiene una instancia del servicio ThreatFox."""
    return ThreatFoxService()

def get_ai_service() -> AIService:
    """Obtiene una instancia del servicio de IA."""
    return AIService()

def get_url_check_service(db: AsyncSession) -> URLCheckService:
    """Obtiene una instancia del servicio de verificación de URLs."""
    return URLCheckService(db)

# Endpoints existentes
@router.post("/check-url", response_model=URLCheckResponse)
async def check_url(
    request: URLCheckRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_session)
):
    """
    Verifica una URL usando servicios de seguridad.
    """
    try:
        otx_service = get_otx_service()
        url_check_service = get_url_check_service(db)

        result = await otx_service.check_url(
            url=str(request.url),
            user_role=current_user.role
        )

        await url_check_service.log_url_check(
            user_id=current_user.id,
            url=str(request.url),
            result=result,
            description=request.description
        )

        logger.info(f"URL verificada exitosamente: {request.url}")
        return URLCheckResponse(**result)

    except InvalidURLError as e:
        logger.warning(f"URL inválida: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except ServiceError as e:
        logger.error(f"Error en servicio: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        raise HTTPException(status_code=500, detail=f"Error al verificar URL: {str(e)}")

@router.get("/url-checks", response_model=List[URLCheckResponse])
async def get_url_checks(
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_session)
):
    """
    Obtiene el historial de verificaciones del usuario.
    """
    try:
        url_check_service = get_url_check_service(db)
        checks = await url_check_service.get_user_url_checks(
            user_id=current_user.id,
            skip=skip,
            limit=limit
        )
        return [URLCheckResponse.from_orm(check) for check in checks]
    except Exception as e:
        logger.error(f"Error obteniendo historial: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo historial: {str(e)}"
        )

@router.get("/stats")
async def get_security_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_session)
):
    """
    Obtiene estadísticas de seguridad (solo para administradores).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Solo administradores pueden ver estadísticas"
        )

    try:
        url_check_service = get_url_check_service(db)
        return await url_check_service.get_security_stats()
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Error obteniendo estadísticas: {str(e)}"
        )

# Nuevos endpoints
@router.post("/analyze-file", response_model=FileAnalysisResponse)
async def analyze_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_session)
):
    """
    Analiza un archivo usando múltiples servicios de seguridad.
    """
    try:
        # Verificar tamaño del archivo
        content = await file.read()
        file_size = len(content)

        if file_size > settings.MAX_SCAN_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"Archivo demasiado grande. Máximo permitido: {settings.MAX_SCAN_SIZE/1024/1024}MB"
            )

        # Analizar con VirusTotal
        vt_service = get_virustotal_service()
        result = await vt_service.analyze_file(content, file.filename)

        # Verificar límites de usuario
        url_check_service = get_url_check_service(db)
        if not await url_check_service.check_user_limits(current_user):
            raise HTTPException(
                status_code=429,
                detail="Has alcanzado el límite diario de análisis"
            )

        # Registrar el análisis
        await url_check_service.log_file_check(
            user_id=current_user.id,
            filename=file.filename,
            result=result
        )

        logger.info(f"Archivo analizado exitosamente: {file.filename}")
        return FileAnalysisResponse(**result)

    except Exception as e:
        logger.error(f"Error analizando archivo: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error analizando archivo: {str(e)}"
        )

@router.post("/analyze-combined", response_model=CombinedAnalysisResponse)
async def analyze_combined(
    request: URLCheckRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_session)
):
    """
    Analiza una URL usando múltiples servicios y proporciona un análisis combinado.
    """
    try:
        # Inicializar servicios
        otx_service = get_otx_service()
        vt_service = get_virustotal_service()
        sb_service = get_safebrowsing_service()
        tf_service = get_threatfox_service()
        ai_service = get_ai_service()

        # Realizar análisis en paralelo
        results = await asyncio.gather(
            otx_service.check_url(str(request.url), current_user.role),
            vt_service.analyze_url(str(request.url)),
            sb_service.check_url(str(request.url)),
            tf_service.check_ioc(str(request.url))
        )

        otx_result, vt_result, sb_result, tf_result = results

        # Preparar resultados para análisis de IA
        combined_data = {
            'url': request.url,
            'otx_results': otx_result,
            'virustotal_results': vt_result,
            'safebrowsing_results': sb_result,
            'threatfox_results': tf_result
        }

        # Obtener análisis de IA
        ai_analysis = await ai_service.analyze_results(combined_data)

        response = {
            **combined_data,
            'ai_analysis': ai_analysis,
            'risk_score': ai_analysis.get('risk_score', 0),
            'recommendations': ai_analysis.get('recommendations', []),
            'checked_at': datetime.now(),
            'technical_details': ai_analysis.get('technical_details', {}),
            'compliance_notes': ai_analysis.get('compliance_notes', [])
        }

        # Registrar verificación
        url_check_service = get_url_check_service(db)
        await url_check_service.log_url_check(
            user_id=current_user.id,
            url=str(request.url),
            result=response,
            description=request.description
        )

        return CombinedAnalysisResponse(**response)

    except Exception as e:
        logger.error(f"Error en análisis combinado: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error en análisis combinado: {str(e)}"
        )


@router.post("/expert-chat", response_model=ExpertChatResponse)
async def expert_chat(
    request: ExpertChatRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Endpoint para consultar al experto en ciberseguridad.
    """
    try:
        ai_service = get_ai_service()
        response = await ai_service.get_expert_response(request.query, request.context)
        
        return ExpertChatResponse(
            response=response,
            timestamp=datetime.now()
        )

    except Exception as e:
        logger.error(f"Error en chat experto: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error en chat experto: {str(e)}"
        )
