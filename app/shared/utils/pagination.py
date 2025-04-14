# app/shared/utils/pagination.py

from fastapi import Query
from fastapi_pagination import Params, LimitOffsetParams

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


def pagination_params(
        page: int = Query(1, ge=1, description="Número da página"),
        size: int = Query(
            DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Itens por página"
        ),
) -> Params:
    return Params(page=page, size=size)


def limit_offset_params(
        limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Limite de itens"),
        offset: int = Query(0, ge=0, description="Deslocamento"),
) -> LimitOffsetParams:
    return LimitOffsetParams(limit=limit, offset=offset)
