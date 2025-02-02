from pydantic import BaseModel, AnyHttpUrl
from typing import Optional, List, Dict
from datetime import datetime
from fastapi import File, UploadFile

class URLCheckRequest(BaseModel):
    url: str
    description: Optional[str] = None

class URLThreat(BaseModel):
    type: str
    severity: str
    description: str
    source: str = "AlienVault OTX"
    detected_at: datetime

class URLCheckResponse(BaseModel):
    url: str
    otx_results: Optional[Dict]
    virustotal_results: Optional[Dict]
    safebrowsing_results: Optional[Dict]
    threatfox_results: Optional[Dict]
    ai_analysis: Optional[Dict]
    risk_score: float
    recommendations: List[str]
    checked_at: datetime
    technical_details: Optional[Dict]
    compliance_notes: Optional[List[str]]

class ExpertChatRequest(BaseModel):
    query: str
    context: Optional[Dict] = None

class ExpertChatResponse(BaseModel):
    response: str
    timestamp: datetime

class FileAnalysisResponse(BaseModel):
    sha256: str
    md5: str
    size: int
    type: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    stats: Dict[str, int]
    results: List[Dict[str, str]]
    tags: List[str]
    reputation: int

class CombinedAnalysisResponse(BaseModel):
    virustotal_results: Optional[Dict]
    otx_results: Optional[Dict]
    haveibeenpwned_results: Optional[Dict]
    ai_analysis: Optional[Dict]
    risk_score: float
    recommendations: List[str]
    checked_at: datetime
class AIAnalysis(BaseModel):
    analysis: str
    risk_summary: str
    recommendations: List[str]
    compliance_notes: List[str]
    technical_details: Dict

class CombinedAnalysisResponse(BaseModel):
    url: str
    otx_results: Optional[Dict]
    virustotal_results: Optional[Dict]
    safebrowsing_results: Optional[Dict]
    threatfox_results: Optional[Dict]
    ai_analysis: Optional[AIAnalysis]
    risk_score: float
    recommendations: List[str]
    checked_at: datetime
    technical_details: Optional[Dict]
    compliance_notes: Optional[List[str]]
class ExpertChatRequest(BaseModel):
    query: str
    context: Optional[Dict] = None

class ExpertChatResponse(BaseModel):
    response: str
    timestamp: datetime
