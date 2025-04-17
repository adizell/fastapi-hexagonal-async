# docs/architecture.md
# Project Architecture Documentation

## Hexagonal Architecture Overview

This project is built following the principles of Hexagonal Architecture (also known as Ports and Adapters). This architectural pattern focuses on separating the core business logic from external concerns like databases, APIs, and UIs.

### Key Concepts

- **Domain Layer**: Contains the business logic, entities, and domain services
- **Application Layer**: Defines use cases that orchestrate domain entities to accomplish business goals
- **Adapters Layer**: Implements interfaces to external systems like databases, APIs, or UIs

### Benefits

1. **Modularity**: Each component has a single responsibility
2. **Testability**: Business logic can be tested in isolation without dependencies
3. **Flexibility**: External systems can be replaced without affecting core logic
4. **Maintainability**: Clear separation of concerns makes the codebase easier to maintain

## Project Structure