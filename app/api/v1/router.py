# app/api/v1/router.py

from fastapi import APIRouter
from app.api.v1.endpoints import (
    user,
    client_auth
)

api_router = APIRouter()

# Incluir os routers dos endpoints
api_router.include_router(user.router, prefix="/user", tags=["User"])

# Incluir routers dos clients (JWT e URL)
api_router.include_router(client_auth.jwt_router)
api_router.include_router(client_auth.create_url_router)
api_router.include_router(client_auth.update_url_router)
