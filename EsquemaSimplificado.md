# Esquema Simplificado

## Vantagens

- Estrutura mais enxuta e de fácil entendimento, ideal para sistemas com requisitos menos complexos.
- Menor barreira inicial para novos integrantes da equipe.
- Menos overhead para iniciar e manter se o escopo for controlado.

## Desvantagens

- Pode precisar de adaptações ou extensões futuras caso o sistema cresça e passe a demandar integrações ou funcionalidades avançadas.


### Root Project
```python
app/
├── adapters/
│   ├── inbound/
│   │   └── api/
│   │       ├── v1/
│   │       │   ├── endpoints/
│   │       │   │   ├── client_auth.py
│   │       │   │   └── user.py
│   │       │   └── router.py
│   │       └── deps.py
│   ├── outbound/
│   │   ├── persistence/
│   │   │   ├── repositories/
│   │   │   │   ├── client_repository.py       # Implementa interface de repositório do domínio
│   │   │   │   └── user_repository.py           # "
│   │   │   ├── models/                          # Pode migrar dos models atuais
│   │   │   │   ├── auth_content_type.py
│   │   │   │   ├── auth_group_permissions.py
│   │   │   │   ├── auth_group.py
│   │   │   │   ├── auth_permission.py
│   │   │   │   ├── client.py
│   │   │   │   ├── user_access_group.py
│   │   │   │   ├── user_access_permission.py
│   │   │   │   └── user.py
│   │   │   ├── database.py                     # Configuração e conexão com o BD
│   │   │   └── seeds/
│   │   │       ├── permissions.py
│   │   │       └── seed.txt
│   │   └── security/
│   │       ├── auth_client_manager.py
│   │       ├── auth_user_manager.py
│   │       ├── token_gerar.py
│   │       └── token_store.py
│   └── configuration/
│       └── config.py                          # Configurações gerais
│
├── application/
│   ├── dtos/                                  # Dados de transferência (equivalente aos dtos)
│   │   ├── base.py
│   │   ├── client_schemas.py
│   │   ├── client_management_schemas.py
│   │   └── user_schemas.py
│   ├── ports/
│   │   ├── inbound.py                         # Interfaces para adaptação (ex.: contratos de entrada/serviços expostos)
│   │   └── outbound.py                        # Interfaces que definem o comportamento esperado de repositórios,
│   │                                            # serviços externos etc.
│   └── use_cases/                             # Casos de uso ou serviços de aplicação com regras de negócio
│       ├── client_use_cases.py                # Poderia agrupar lógica dos serviços de cliente
│       └── user_use_cases.py                  # Lógica de uso de usuário (pode agrupar também o que está em use_cases/)
│
├── domain/
│   ├── models/                                # Entidades e objetos de domínio
│   │   ├── client.py                          # Entidade Cliente
│   │   └── user.py                            # Entidade Usuário
│   ├── services/                              # Serviços do domínio (lógica de negócio pura)
│   │   ├── client_service.py
│   │   └── user_service.py
│   └── exceptions.py                          # Exceções específicas do domínio
│
├── shared/                                    # Itens comuns e transversais
│   ├── middleware/
│   │   ├── csrf_middleware.py
│   │   ├── exception_middleware.py
│   │   ├── logging_middleware.py
│   │   ├── rate_limiting_middleware.py
│   │   └── security_headers_middleware.py
│   └── utils/
│       ├── email_validation.py
│       ├── input_validation.py
│       └── pagination.py
│
├── infrastructure/                          # Poderia unir configurações e integrações não expostas externamente
│   └── app.tree                              # Se necessário, ou outros artefatos de infraestrutura
│
├── static/
│   └── img/
│       ├── favicon.ico
│       └── favicon.png
│
├── templates/
│   ├── create_client_jwt.html
│   ├── create_client_url.html
│   └── update_client_url.html
│
├── tests/                                    # Reorganize os testes para refletir as camadas (domínio, aplicação, adapters)
│   ├── conftest.py
│   ├── schemas/
│   │   └── test_user_schema.py
│   └── use_cases/
│       └── test_user_use_cases.py
│
└── main.py                                    # Ponto de entrada da aplicação
```