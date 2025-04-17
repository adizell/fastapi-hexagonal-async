# app/domain/models/client_domain_model.py

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Client:
    """Domain model for API client entity."""
    id: int
    client_id: str  # Public identifier
    client_secret: str  # Hashed secret
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
