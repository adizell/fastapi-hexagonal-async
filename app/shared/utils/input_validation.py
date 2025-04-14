# app/shared/utils/input_validation.py

import re
from typing import Optional, Tuple, List, Dict, Any


class InputValidator:
    """
    Classe para validação e sanitização de entradas do usuário,
    complementando as validações do Pydantic.
    """

    # Constantes para limites
    MAX_NAME_LENGTH = 100
    MAX_PASSWORD_LENGTH = 72  # Limite seguro para bcrypt
    MIN_PASSWORD_LENGTH = 8
    MAX_EMAIL_LENGTH = 255
    MAX_STRING_INPUT_LENGTH = 1000  # Limite geral para strings

    # Padrões regex para validação
    # Permite letras, números, espaços, hífens e apóstrofes em nomes
    # Versão simplificada sem \p{L} e \p{N}
    # NAME_PATTERN = re.compile(r'^[A-Za-z0-9\s\-\'\.]+$')  # Não permite caracteres acentuados
    NAME_PATTERN = re.compile(r'^[A-Za-zÀ-ÖØ-öø-ÿ0-9\s\-\'\.]+$')  # Inclui caracteres acentuados
    # Verifica complexidade da senha
    PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$')
    # Padrão para email
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    # Padrão para nomes de slug
    SLUG_PATTERN = re.compile(r'^[a-z0-9\-]+$')
    # Caracteres potencialmente perigosos em entrada comum
    DANGEROUS_CHARS = re.compile(r'[<>\'";%{}\[\]]')

    @classmethod
    def validate_name(cls, name: str) -> Tuple[bool, Optional[str]]:
        """
        Valida um nome para prevenção de injeção.

        Args:
            name: String a ser validada

        Returns:
            Tupla (válido, mensagem_erro)
        """
        if not name or not name.strip():
            return False, "Nome não pode estar vazio"

        if len(name) > cls.MAX_NAME_LENGTH:
            return False, f"Nome é muito longo (máximo {cls.MAX_NAME_LENGTH} caracteres)"

        # Detecta caracteres potencialmente maliciosos
        if cls.DANGEROUS_CHARS.search(name):
            return False, "Nome contém caracteres não permitidos"

        # Valida com padrão
        if not cls.NAME_PATTERN.match(name):
            return False, "Nome contém caracteres inválidos"

        return True, None

    @classmethod
    def sanitize_name(cls, name: str) -> str:
        """
        Sanitiza um nome removendo espaços extras e limitando o tamanho.

        Args:
            name: String a ser sanitizada

        Returns:
            String sanitizada
        """
        # Remove espaços no início e fim e reduz múltiplos espaços internos
        sanitized = re.sub(r'\s+', ' ', name.strip())

        # Trunca se exceder o limite
        if len(sanitized) > cls.MAX_NAME_LENGTH:
            sanitized = sanitized[:cls.MAX_NAME_LENGTH]

        return sanitized

    @classmethod
    def validate_password(cls, password: str) -> Tuple[bool, Optional[str]]:
        """
        Valida uma senha quanto à força e segurança.

        Args:
            password: Senha a ser validada

        Returns:
            Tupla (válido, mensagem_erro)
        """
        if not password:
            return False, "Senha não pode estar vazia"

        if len(password) < cls.MIN_PASSWORD_LENGTH:
            return False, f"Senha deve ter pelo menos {cls.MIN_PASSWORD_LENGTH} caracteres"

        if len(password) > cls.MAX_PASSWORD_LENGTH:
            return False, f"Senha é muito longa (máximo {cls.MAX_PASSWORD_LENGTH} caracteres)"

        # Verificações de complexidade (opcional - comente se muito restritivo)
        if not cls.PASSWORD_PATTERN.match(password):
            return False, "Senha deve conter pelo menos 1 letra maiúscula, 1 minúscula, 1 número e 1 caractere especial"

        return True, None

    @classmethod
    def validate_email(cls, email: str) -> Tuple[bool, Optional[str]]:
        """
        Valida formato e comprimento de email.

        Args:
            email: Email a ser validado

        Returns:
            Tupla (válido, mensagem_erro)
        """
        if not email:
            return False, "Email não pode estar vazio"

        if len(email) > cls.MAX_EMAIL_LENGTH:
            return False, f"Email é muito longo (máximo {cls.MAX_EMAIL_LENGTH} caracteres)"

        if not cls.EMAIL_PATTERN.match(email):
            return False, "Formato de email inválido"

        return True, None

    @classmethod
    def validate_slug(cls, slug: str) -> Tuple[bool, Optional[str]]:
        """
        Valida um slug.

        Args:
            slug: Slug a ser validado

        Returns:
            Tupla (válido, mensagem_erro)
        """
        if not slug:
            return False, "Slug não pode estar vazio"

        if not cls.SLUG_PATTERN.match(slug):
            return False, "Slug deve conter apenas letras minúsculas, números e hífens"

        return True, None

    @classmethod
    def sanitize_string(cls, text: str, max_length: Optional[int] = None) -> str:
        """
        Sanitiza uma string genérica.

        Args:
            text: String a ser sanitizada
            max_length: Comprimento máximo (opcional)

        Returns:
            String sanitizada
        """
        if not max_length:
            max_length = cls.MAX_STRING_INPUT_LENGTH

        # Remove espaços no início e fim
        sanitized = text.strip()

        # Trunca se exceder o limite
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]

        return sanitized

    @classmethod
    def validate_dict_data(cls, data: Dict[str, Any], rules: Dict[str, Dict[str, Any]]) -> List[str]:
        """
        Valida um dicionário de dados conforme regras específicas.

        Args:
            data: Dicionário de dados a validar
            rules: Regras de validação no formato:
                  {'campo': {'type': tipo, 'required': bool, 'max_length': int, ...}}

        Returns:
            Lista de mensagens de erro (vazia se tudo ok)
        """
        errors = []

        for field, rule in rules.items():
            # Verificar campos obrigatórios
            if rule.get('required', False) and (field not in data or data[field] is None):
                errors.append(f"Campo '{field}' é obrigatório")
                continue

            # Pular validação de campos ausentes não obrigatórios
            if field not in data or data[field] is None:
                continue

            value = data[field]

            # Validar tipo
            expected_type = rule.get('type')
            if expected_type and not isinstance(value, expected_type):
                errors.append(f"Campo '{field}' deve ser do tipo {expected_type.__name__}")
                continue

            # Validar strings
            if isinstance(value, str):
                # Comprimento máximo
                max_length = rule.get('max_length', cls.MAX_STRING_INPUT_LENGTH)
                if len(value) > max_length:
                    errors.append(f"Campo '{field}' excede o tamanho máximo de {max_length} caracteres")

                # Comprimento mínimo
                min_length = rule.get('min_length', 0)
                if len(value) < min_length:
                    errors.append(f"Campo '{field}' deve ter pelo menos {min_length} caracteres")

                # Padrão regex
                pattern = rule.get('pattern')
                if pattern and not pattern.match(value):
                    errors.append(f"Campo '{field}' tem formato inválido")

                # Verificação de caracteres perigosos
                if rule.get('check_dangerous', False) and cls.DANGEROUS_CHARS.search(value):
                    errors.append(f"Campo '{field}' contém caracteres não permitidos")

        return errors

