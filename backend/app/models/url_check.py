from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class URLCheck(Base):
    __tablename__ = "url_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    url = Column(String, nullable=False)
    is_malicious = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    threats = Column(JSON, nullable=False, default=list)
    recommendations = Column(JSON, nullable=False, default=list)
    detailed_analysis = Column(JSON, nullable=True)
    checked_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    description = Column(String, nullable=True)
    source = Column(String, nullable=False, default='otx')
    status = Column(String, nullable=False, default='completed')

    # Relación con usuario
    user = relationship("User", back_populates="url_checks")

    def __repr__(self):
        return f"<URLCheck(id={self.id}, url={self.url}, is_malicious={self.is_malicious})>"

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'url': self.url,
            'is_malicious': self.is_malicious,
            'risk_score': self.risk_score,
            'threats': self.threats,
            'recommendations': self.recommendations,
            'detailed_analysis': self.detailed_analysis,
            'checked_at': self.checked_at,
            'updated_at': self.updated_at,
            'description': self.description,
            'source': self.source,
            'status': self.status
        }
