# Esquema Detalhado

## Vantagens

- **Altamente modular e preparado para um ambiente robusto:**  
  Suporte estruturado para múltiplos protocolos (REST, GRPC, GraphQL, Websockets) e integrações (cache, messaging, storage, external services).

- **Separação clara entre cada camada e componente:**  
  Controllers, dependências, DTOs, repositórios e casos de uso, favorecendo a escalabilidade e o isolamento de responsabilidades.

- **Estrutura preparada para testes automatizados:**  
  Abrange testes unitários, de integração, funcionais e de performance, juntamente com processos de CI/CD bem definidos.

## Desvantagens

- **Maior quantidade de diretórios e arquivos:**  
  Pode aumentar a complexidade inicial e exigir mais tempo para configuração e onboarding da equipe.

- **Possível excesso de granularidade:**  
  Se o sistema não demandar suporte para múltiplos protocolos desde o início, a estrutura pode parecer “overkill”.

### Root Project
```python
app/
├── adapters/
│   ├── inbound/
│   │   ├── api/
│   │   │   ├── docs/
│   │   │   │   ├── openapi.py                  # Configuração e personalização do OpenAPI
│   │   │   │   ├── swagger_ui.py               # Configuração do Swagger UI
│   │   │   │   └── schemas/                    # Esquemas reutilizáveis para documentação
│   │   │   │       ├── auth.py
│   │   │   │       ├── common.py
│   │   │   │       └── error_responses.py
│   │   │   ├── dependencies/                   # Dependências da API para injeção
│   │   │   │   ├── auth.py                     # Funções de dependência para autenticação
│   │   │   │   ├── pagination.py               # Funções para paginação
│   │   │   │   └── repositories.py             # Injeção de repositórios
│   │   │   ├── websockets/                     # Suporte a websockets
│   │   │   │   ├── connection_manager.py
│   │   │   │   └── endpoints.py
│   │   │   ├── health/                         # Endpoints de health check
│   │   │   │   └── routes.py
│   │   │   ├── v1/                             # API versão 1
│   │   │   │   ├── controllers/                # Controladores por domínio
│   │   │   │   │   ├── auth_controller.py
│   │   │   │   │   ├── client_controller.py
│   │   │   │   │   └── user_controller.py
│   │   │   │   ├── routes/                     # Rotas por domínio
│   │   │   │   │   ├── auth_routes.py
│   │   │   │   │   ├── client_routes.py
│   │   │   │   │   └── user_routes.py
│   │   │   │   ├── responses/                  # Modelos de resposta
│   │   │   │   │   ├── auth_responses.py
│   │   │   │   │   ├── client_responses.py
│   │   │   │   │   └── user_responses.py
│   │   │   │   └── router.py                   # Agrega todas as rotas v1
│   │   │   ├── v2/                             # Espaço para versão futura
│   │   │   │   └── router.py
│   │   │   └── api.py                          # Montagem principal da API
│   │   ├── grpc/                               # Suporte futuro para gRPC
│   │   │   └── server.py
│   │   └── graphql/                            # Suporte futuro para GraphQL
│   │       └── schema.py
│   ├── outbound/
│   │   ├── persistence/
│   │   │   ├── repositories/                   # Implementações concretas dos repositórios
│   │   │   │   ├── base_repository.py          # Classe base para repositórios
│   │   │   │   ├── client_repository.py
│   │   │   │   └── user_repository.py
│   │   │   ├── models/                         # Modelos ORM
│   │   │   │   ├── base_model.py               # Modelo base com campos comuns
│   │   │   │   ├── auth/
│   │   │   │   │   ├── client.py
│   │   │   │   │   ├── permission.py
│   │   │   │   │   └── token.py
│   │   │   │   └── user/
│   │   │   │       ├── user.py
│   │   │   │       └── user_group.py
│   │   │   ├── migrations/                     # Gerenciamento de migrações do banco
│   │   │   │   ├── env.py
│   │   │   │   ├── README.md
│   │   │   │   ├── script.py.mako
│   │   │   │   └── versions/
│   │   │   ├── database.py                     # Configuração de conexão com o banco
│   │   │   └── seeders/                        # Dados iniciais
│   │   │       ├── base_seeder.py
│   │   │       ├── permission_seeder.py
│   │   │       └── run_seeders.py
│   │   ├── security/
│   │   │   ├── authentication/
│   │   │   │   ├── jwt_handler.py
│   │   │   │   ├── oauth_handler.py
│   │   │   │   └── password_handler.py
│   │   │   ├── authorization/
│   │   │   │   ├── permission_checker.py
│   │   │   │   └── rbac_manager.py
│   │   │   └── rate_limiter/
│   │   │       └── redis_rate_limiter.py
│   │   ├── messaging/                          # Mensageria
│   │   │   ├── events/
│   │   │   │   ├── base_event.py
│   │   │   │   ├── user_events.py
│   │   │   │   └── client_events.py
│   │   │   ├── kafka/
│   │   │   │   ├── producer.py
│   │   │   │   └── consumer.py
│   │   │   └── rabbitmq/
│   │   │       ├── producer.py
│   │   │       └── consumer.py
│   │   ├── cache/
│   │   │   ├── base_cache.py
│   │   │   ├── redis_cache.py
│   │   │   └── memory_cache.py
│   │   ├── storage/
│   │   │   ├── base_storage.py
│   │   │   ├── s3_storage.py
│   │   │   └── local_storage.py
│   │   ├── external/                           # Integração com sistemas externos
│   │   │   ├── base_client.py
│   │   │   ├── payment_gateway/
│   │   │   │   └── payment_client.py
│   │   │   └── notification/
│   │   │       ├── email_client.py
│   │   │       └── sms_client.py
│   │   └── telemetry/                          # Telemetria e observabilidade
│   │       ├── tracing.py
│   │       ├── metrics.py
│   │       └── logging_manager.py
│   └── configuration/
│       ├── settings/
│       │   ├── app_settings.py
│       │   ├── auth_settings.py
│       │   └── database_settings.py
│       ├── container.py                        # Contêiner de injeção de dependência
│       └── config.py                           # Carregamento das configurações
├── application/
│   ├── dtos/                                   # DTOs compartilhados
│   │   ├── base_dto.py
│   │   ├── auth/
│   │   │   ├── client_dtos.py
│   │   │   ├── token_dtos.py
│   │   │   └── permission_dtos.py
│   │   └── user/
│   │       ├── user_dtos.py
│   │       └── user_group_dtos.py
│   ├── ports/
│   │   ├── inbound/                            # Portas de entrada
│   │   │   ├── auth_use_cases.py
│   │   │   ├── client_use_cases.py
│   │   │   └── user_use_cases.py
│   │   └── outbound/                           # Portas de saída
│   │       ├── repositories/
│   │       │   ├── base_repository_port.py
│   │       │   ├── client_repository_port.py
│   │       │   └── user_repository_port.py
│   │       ├── security/
│   │       │   ├── token_service_port.py
│   │       │   └── password_service_port.py
│   │       ├── messaging/
│   │       │   └── event_publisher_port.py
│   │       ├── cache/
│   │       │   └── cache_service_port.py
│   │       └── external/
│   │           ├── notification_service_port.py
│   │           └── payment_service_port.py
│   └── use_cases/                              # Casos de uso organizados por domínio
│       ├── auth/
│       │   ├── login_use_case.py
│       │   ├── logout_use_case.py
│       │   ├── refresh_token_use_case.py
│       │   └── register_client_use_case.py
│       ├── user/
│       │   ├── create_user_use_case.py
│       │   ├── update_user_use_case.py
│       │   ├── delete_user_use_case.py
│       │   ├── get_user_use_case.py
│       │   └── manage_permissions_use_case.py
│       └── client/
│           ├── create_client_use_case.py
│           ├── update_client_use_case.py
│           ├── delete_client_use_case.py
│           └── get_client_use_case.py
├── domain/
│   ├── models/                                 # Entidades e objetos de valor
│   │   ├── common/
│   │   │   ├── value_objects/
│   │   │   │   ├── email.py
│   │   │   │   ├── password.py
│   │   │   │   └── identifier.py
│   │   │   └── entity.py                       # Classe base para entidades
│   │   ├── auth/
│   │   │   ├── client.py
│   │   │   ├── permission.py
│   │   │   └── token.py
│   │   └── user/
│   │       ├── user.py
│   │       └── user_group.py
│   ├── services/                               # Serviços do domínio
│   │   ├── auth/
│   │   │   ├── token_service.py
│   │   │   └── permission_service.py
│   │   └── user/
│   │       └── password_service.py
│   ├── events/                                 # Eventos do domínio
│   │   ├── base_event.py
│   │   ├── user_events.py
│   │   └── client_events.py
│   └── exceptions/                             # Exceções do domínio
│       ├── base_exception.py
│       ├── auth_exceptions.py
│       └── user_exceptions.py
├── shared/                                     # Recursos compartilhados
│   ├── middleware/
│   │   ├── authentication_middleware.py
│   │   ├── exception_middleware.py
│   │   ├── logging_middleware.py
│   │   ├── rate_limit_middleware.py
│   │   └── security_headers_middleware.py
│   ├── utils/
│   │   ├── pagination.py
│   │   ├── validation.py
│   │   ├── date_utils.py
│   │   └── string_utils.py
│   ├── concurrency/
│   │   ├── task_manager.py                     # Gerenciamento de tarefas assíncronas
│   │   └── background_tasks.py
│   └── constants/
│       ├── error_codes.py
│       └── app_constants.py
├── infrastructure/                             # Configurações de infraestrutura
│   ├── di/                                     # Dependence Injection
│   │   ├── container.py                        # Configuração do contêiner DI
│   │   └── providers.py                        # Provedores para injeção
│   ├── logging/
│   │   ├── conf/
│   │   │   └── logging.yaml
│   │   └── log_setup.py
│   ├── telemetry/
│   │   ├── opentelemetry_setup.py
│   │   └── prometheus_setup.py
│   └── security/
│       ├── cors_setup.py
│       └── security_headers.py
├── static/                                     # Recursos estáticos
│   ├── assets/
│   │   └── img/
│   │       └── favicon.ico
│   └── docs/
│       └── redoc-static.html
├── templates/                                  # Templates HTML
│   ├── auth/
│   │   ├── email_templates/
│   │   │   ├── password_reset.html
│   │   │   └── verification.html
│   │   └── pages/
│   │       └── login.html
│   └── swagger_ui/
│       └── custom.html
├── tests/                                      # Testes organizados por tipo e camada
│   ├── conftest.py
│   ├── fixtures/
│   │   ├── auth_fixtures.py
│   │   └── user_fixtures.py
│   ├── integration/
│   │   ├── api/
│   │   │   ├── test_auth_endpoints.py
│   │   │   ├── test_client_endpoints.py
│   │   │   └── test_user_endpoints.py
│   │   └── persistence/
│   │       ├── test_client_repository.py
│   │       └── test_user_repository.py
│   ├── unit/
│   │   ├── domain/
│   │   │   ├── models/
│   │   │   │   ├── test_user.py
│   │   │   │   └── test_client.py
│   │   │   └── services/
│   │   │       └── test_token_service.py
│   │   └── application/
│   │       └── use_cases/
│   │           ├── auth/
│   │           │   └── test_login_use_case.py
│   │           └── user/
│   │               └── test_create_user_use_case.py
│   ├── functional/
│   │   └── test_user_workflow.py
│   └── performance/
│       └── locustfile.py
├── scripts/                                    # Scripts utilitários
│   ├── db/
│   │   ├── create_migration.sh
│   │   └── seed_data.py
│   ├── docker/
│   │   ├── start.sh
│   │   └── entrypoint.sh
│   └── ci/
│       ├── test.sh
│       └── deploy.sh
├── docs/                                       # Documentação do projeto
│   ├── architecture/
│   │   ├── overview.md
│   │   └── diagrams/
│   │       ├── hexagonal.svg
│   │       └── sequence_diagrams/
│   ├── api/
│   │   └── api_docs.md
│   └── development/
│       ├── contributing.md
│       ├── code_style.md
│       └── testing.md
├── deploy/                                     # Arquivos de implantação
│   ├── docker/
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   └── docker-compose.prod.yml
│   ├── kubernetes/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── ingress.yaml
│   └── terraform/
│       ├── main.tf
│       └── variables.tf
├── .github/                                    # Configurações CI/CD
│   └── workflows/
│       ├── test.yml
│       ├── lint.yml
│       └── deploy.yml
├── .pre-commit-config.yaml                     # Verificações pré-commit
├── pyproject.toml                              # Dependências e metadados
├── poetry.lock                                 # Versões fixas de dependências
├── .env.example                                # Exemplo de variáveis de ambiente
├── README.md                                   # Documentação principal
├── CHANGELOG.md                                # Registro de alterações
└── main.py                                     # Ponto de entrada da aplicação
```