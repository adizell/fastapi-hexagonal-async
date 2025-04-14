# app/shared/utils/email_validation.py
"""
Utilitários para validação e normalização de emails.
"""

import re
from typing import Tuple

# Regex para validação básica de email
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Valida um endereço de email.

    Args:
        email: O endereço de email a ser validado

    Returns:
        Tupla (válido, mensagem de erro)
    """
    if not email:
        return False, "Email não pode estar vazio"

    # Normalizar removendo espaços
    email = email.strip().lower()

    # Verificar tamanho
    if len(email) > 255:
        return False, "Email não pode exceder 255 caracteres"

    # Validar formato básico com regex
    if not EMAIL_REGEX.match(email):
        return False, "Formato de email inválido"

    return True, ""


def normalize_email(email: str) -> str:
    """
    Normaliza um endereço de email removendo espaços e convertendo para minúsculas.

    Args:
        email: O endereço de email a ser normalizado

    Returns:
        Email normalizado
    """
    return email.strip().lower()
