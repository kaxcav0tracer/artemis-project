"""SQLAlchemy ORM models for Artemis SOAR"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Boolean
from .database import Base


class ThreatCache(Base):
    """Cache de reputação de ameaças - armazena resultados do VirusTotal

    Attributes:
        ioc_value: Valor do indicador de comprometimento (IP, Hash, etc) - Primary Key
        ioc_type: Tipo do IOC ("IP", "HASH", "DOMAIN", etc)
        reputation_score: Contagem de fornecedores maliciosos (0-100+)
        last_seen: Data/hora da última detecção
        expires_at: Data/hora de expiração do cache (24h por padrão)
        action_taken: Ação recomendada ("BLOCK", "ALLOW", "MONITOR")
        created_at: Timestamp de criação
        updated_at: Timestamp da última atualização
        fortigate_synced: Se o IP foi sincronizado com FortiGate com sucesso
        fortigate_response: Resposta da API FortiGate
        fortigate_sync_error: Erro ocorrido durante sincronização com FortiGate
    """

    __tablename__ = "threat_cache"

    ioc_value = Column(String(255), primary_key=True, index=True, nullable=False)
    ioc_type = Column(String(50), nullable=False, default="IP")
    reputation_score = Column(Integer, nullable=False, default=0)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    action_taken = Column(String(50), nullable=False, default="ALLOW")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    fortigate_synced = Column(Boolean, nullable=False, default=False)
    fortigate_response = Column(String(500), nullable=True)
    fortigate_sync_error = Column(String(500), nullable=True)

    def __repr__(self) -> str:
        return f"<ThreatCache(ioc_value='{self.ioc_value}', action='{self.action_taken}', reputation={self.reputation_score}, fg_synced={self.fortigate_synced})>"
