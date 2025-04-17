# app/adapters/inbound/api/v1/router.py

from fastapi import APIRouter
from app.adapters.inbound.api.v1.endpoints import client_endpoint, user_endpoint, auth_endpoint

api_router = APIRouter()

# Incluir os routers dos endpoints
api_router.include_router(auth_endpoint.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(user_endpoint.router, prefix="/user", tags=["User"])

# Incluir routers dos clients (JWT e URL)
api_router.include_router(client_endpoint.jwt_router)
api_router.include_router(client_endpoint.create_url_router)
api_router.include_router(client_endpoint.update_url_router)
