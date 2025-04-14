# app/adapters/outbound/persistence/seeds/permissions.py

"""
Script de seed para permissões e grupos de acesso.

Este módulo popula o banco de dados com permissões, grupos
e atribuições de permissões a grupos necessários para o
funcionamento do sistema de controle de acesso.
"""

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from decouple import config

from app.db.models.auth_group import AuthGroup
from app.db.models.auth_permission import AuthPermission
from app.db.models.auth_content_type import AuthContentType
from app.db.base import Base

# Configurações do banco
TEST_MODE = config("TEST_MODE", default=False, cast=bool)
DB_URL = config("DB_URL_TEST") if TEST_MODE else config("DB_URL")
engine = create_engine(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dados base
groups = ["admin", "user"]

# Permissões de usuário/species/pets existentes
content_types = [
    {"app_label": "user", "model": "register_user"},
    {"app_label": "user", "model": "login_user"},
    {"app_label": "specie", "model": "list_species"},
    {"app_label": "specie", "model": "add_specie"},
    {"app_label": "specie", "model": "update_specie"},
    {"app_label": "specie", "model": "delete_specie"},
    {"app_label": "pet", "model": "add_pet"},
    {"app_label": "pet", "model": "list_pets"},
    {"app_label": "pet", "model": "update_pet"},
    {"app_label": "pet", "model": "delete_pet"},

    # Novas permissões para categorias - Environment
    {"app_label": "category", "model": "list_category_environment"},
    {"app_label": "category", "model": "add_category_environment"},
    {"app_label": "category", "model": "update_category_environment"},
    {"app_label": "category", "model": "delete_category_environment"},
    {"app_label": "category", "model": "view_category_environment"},

    # Novas permissões para categorias - Condition
    {"app_label": "category", "model": "list_category_condition"},
    {"app_label": "category", "model": "add_category_condition"},
    {"app_label": "category", "model": "update_category_condition"},
    {"app_label": "category", "model": "delete_category_condition"},
    {"app_label": "category", "model": "view_category_condition"},

    # Novas permissões para categorias - Purpose
    {"app_label": "category", "model": "list_category_purpose"},
    {"app_label": "category", "model": "add_category_purpose"},
    {"app_label": "category", "model": "update_category_purpose"},
    {"app_label": "category", "model": "delete_category_purpose"},
    {"app_label": "category", "model": "view_category_purpose"},

    # Novas permissões para categorias - Habitat
    {"app_label": "category", "model": "list_category_habitat"},
    {"app_label": "category", "model": "add_category_habitat"},
    {"app_label": "category", "model": "update_category_habitat"},
    {"app_label": "category", "model": "delete_category_habitat"},
    {"app_label": "category", "model": "view_category_habitat"},

    # Novas permissões para categorias - Origin
    {"app_label": "category", "model": "list_category_origin"},
    {"app_label": "category", "model": "add_category_origin"},
    {"app_label": "category", "model": "update_category_origin"},
    {"app_label": "category", "model": "delete_category_origin"},
    {"app_label": "category", "model": "view_category_origin"},

    # Novas permissões para categorias - Size
    {"app_label": "category", "model": "list_category_size"},
    {"app_label": "category", "model": "add_category_size"},
    {"app_label": "category", "model": "update_category_size"},
    {"app_label": "category", "model": "delete_category_size"},
    {"app_label": "category", "model": "view_category_size"},

    # Novas permissões para categorias - Age
    {"app_label": "category", "model": "list_category_age"},
    {"app_label": "category", "model": "add_category_age"},
    {"app_label": "category", "model": "update_category_age"},
    {"app_label": "category", "model": "delete_category_age"},
    {"app_label": "category", "model": "view_category_age"},
]

# Distribuição de permissões por grupo
group_permissions = {
    "admin": [
        # Permissões existentes
        "register_user", "login_user", "list_species",
        "add_pet", "list_pets", "update_pet", "delete_pet",

        # Apenas visualização/listagem de categorias (para ambos grupos)
        "list_category_environment", "view_category_environment",
        "list_category_condition", "view_category_condition",
        "list_category_purpose", "view_category_purpose",
        "list_category_habitat", "view_category_habitat",
        "list_category_origin", "view_category_origin",
        "list_category_size", "view_category_size",
        "list_category_age", "view_category_age",

        # Permissões administrativas de categorias (apenas para admin)
        #        "add_category_environment", "update_category_environment", "delete_category_environment",
        #        "add_category_condition", "update_category_condition", "delete_category_condition",
        #        "add_category_purpose", "update_category_purpose", "delete_category_purpose",
        #        "add_category_habitat", "update_category_habitat", "delete_category_habitat",
        #        "add_category_origin", "update_category_origin", "delete_category_origin",
        #        "add_category_size", "update_category_size", "delete_category_size",
        #        "add_category_age", "update_category_age", "delete_category_age",
    ],
    "user": [
        # Permissões existentes
        "register_user", "login_user", "list_species",
        "add_pet", "list_pets", "update_pet", "delete_pet",

        # Apenas visualização/listagem de categorias
        "list_category_environment", "view_category_environment",
        "list_category_condition", "view_category_condition",
        "list_category_purpose", "view_category_purpose",
        "list_category_habitat", "view_category_habitat",
        "list_category_origin", "view_category_origin",
        "list_category_size", "view_category_size",
        "list_category_age", "view_category_age",
    ]
}


def run_permissions_seed():
    session = SessionLocal()
    try:
        # Criação de grupos
        group_objs = {}
        for name in groups:
            group = session.query(AuthGroup).filter_by(name=name).first()
            if not group:
                group = AuthGroup(name=name)
                session.add(group)
                print(f"🟢 Grupo '{name}' criado com sucesso.")
            else:
                print(f"🟡 Grupo '{name}' já existe.")
            group_objs[name] = group

        # Criação de content types e permissões
        permission_objs = {}
        for ct in content_types:
            ct_obj = session.query(AuthContentType).filter_by(
                app_label=ct["app_label"], model=ct["model"]
            ).first()
            if not ct_obj:
                ct_obj = AuthContentType(app_label=ct["app_label"], model=ct["model"])
                session.add(ct_obj)
                session.flush()
                print(f"🟢 ContentType '{ct['app_label']}.{ct['model']}' criado.")
            else:
                print(f"🟡 ContentType '{ct['app_label']}.{ct['model']}' já existe.")

            codename = ct["model"]
            perm = session.query(AuthPermission).filter_by(codename=codename).first()
            if not perm:
                perm = AuthPermission(
                    name=f"Can {codename}",
                    codename=codename,
                    content_type_id=ct_obj.id,
                )
                session.add(perm)
                session.flush()
                print(f"🟢 Permissão '{codename}' criada.")
            else:
                print(f"🟡 Permissão '{codename}' já existe.")

            permission_objs[codename] = perm

        # Associação entre permissões e grupos
        for group_name, perms in group_permissions.items():
            group = group_objs[group_name]
            for codename in perms:
                permission = permission_objs.get(codename)
                if permission and permission not in group.permissions:
                    group.permissions.append(permission)
                    print(f"🟢 Permissão '{codename}' adicionada ao grupo '{group_name}'.")
                elif permission:
                    print(f"🟡 Grupo '{group_name}' já possui a permissão '{codename}'.")

        session.commit()
        print("✅ Seed finalizado com sucesso.")
    except Exception as e:
        session.rollback()
        print(f"🔴 Erro ao executar seed: {e}")
    finally:
        session.close()


if __name__ == "__main__":
    run_permissions_seed()

# import logging
# from sqlalchemy.orm import Session
#
# from app.db.models.auth_group import AuthGroup
# from app.db.models.auth_permission import AuthPermission
# from app.db.models.auth_content_type import AuthContentType
#
# # Configurar logger
# logger = logging.getLogger(__name__)
#
# # Dados de grupos
# DEFAULT_GROUPS = ["admin", "user"]
#
# # Dados de tipos de conteúdo e permissões
# CONTENT_TYPES = [
#     # Permissões de usuário
#     {"app_label": "user", "model": "register_user"},
#     {"app_label": "user", "model": "login_user"},
#
#     # Permissões de espécie
#     {"app_label": "specie", "model": "list_species"},
#     {"app_label": "specie", "model": "add_specie"},
#     {"app_label": "specie", "model": "update_specie"},
#     {"app_label": "specie", "model": "delete_specie"},
#
#     # Permissões de pet
#     {"app_label": "pet", "model": "add_pet"},
#     {"app_label": "pet", "model": "list_pets"},
#     {"app_label": "pet", "model": "update_pet"},
#     {"app_label": "pet", "model": "delete_pet"},
#
#     # Permissões de categoria - Environment
#     {"app_label": "category", "model": "list_category_environment"},
#     {"app_label": "category", "model": "add_category_environment"},
#     {"app_label": "category", "model": "update_category_environment"},
#     {"app_label": "category", "model": "delete_category_environment"},
#     {"app_label": "category", "model": "view_category_environment"},
#
#     # Permissões de categoria - Condition
#     {"app_label": "category", "model": "list_category_condition"},
#     {"app_label": "category", "model": "add_category_condition"},
#     {"app_label": "category", "model": "update_category_condition"},
#     {"app_label": "category", "model": "delete_category_condition"},
#     {"app_label": "category", "model": "view_category_condition"},
#
#     # Permissões de categoria - Purpose
#     {"app_label": "category", "model": "list_category_purpose"},
#     {"app_label": "category", "model": "add_category_purpose"},
#     {"app_label": "category", "model": "update_category_purpose"},
#     {"app_label": "category", "model": "delete_category_purpose"},
#     {"app_label": "category", "model": "view_category_purpose"},
#
#     # Permissões de categoria - Habitat
#     {"app_label": "category", "model": "list_category_habitat"},
#     {"app_label": "category", "model": "add_category_habitat"},
#     {"app_label": "category", "model": "update_category_habitat"},
#     {"app_label": "category", "model": "delete_category_habitat"},
#     {"app_label": "category", "model": "view_category_habitat"},
#
#     # Permissões de categoria - Origin
#     {"app_label": "category", "model": "list_category_origin"},
#     {"app_label": "category", "model": "add_category_origin"},
#     {"app_label": "category", "model": "update_category_origin"},
#     {"app_label": "category", "model": "delete_category_origin"},
#     {"app_label": "category", "model": "view_category_origin"},
#
#     # Permissões de categoria - Size
#     {"app_label": "category", "model": "list_category_size"},
#     {"app_label": "category", "model": "add_category_size"},
#     {"app_label": "category", "model": "update_category_size"},
#     {"app_label": "category", "model": "delete_category_size"},
#     {"app_label": "category", "model": "view_category_size"},
#
#     # Permissões de categoria - Age
#     {"app_label": "category", "model": "list_category_age"},
#     {"app_label": "category", "model": "add_category_age"},
#     {"app_label": "category", "model": "update_category_age"},
#     {"app_label": "category", "model": "delete_category_age"},
#     {"app_label": "category", "model": "view_category_age"},
# ]
#
# # Mapeamento de permissões para grupos
# GROUP_PERMISSIONS = {
#     "admin": [
#         # Todas as permissões de usuário
#         "register_user", "login_user",
#
#         # Todas as permissões de espécie
#         "list_species", "add_specie", "update_specie", "delete_specie",
#
#         # Todas as permissões de pet
#         "add_pet", "list_pets", "update_pet", "delete_pet",
#
#         # Todas as permissões de categorias
#         "list_category_environment", "view_category_environment",
#         # "update_category_environment", "delete_category_environment", "add_category_environment",
#
#         "list_category_condition", "view_category_condition",
#         # "update_category_condition", "delete_category_condition", "add_category_condition",
#
#         "list_category_purpose", "view_category_purpose",
#         # "update_category_purpose", "delete_category_purpose", "add_category_purpose",
#
#         "list_category_habitat", "view_category_habitat",
#         # "update_category_habitat", "delete_category_habitat", "add_category_habitat",
#
#         "list_category_origin", "view_category_origin",
#         # "update_category_origin", "delete_category_origin", "add_category_origin",
#
#         "list_category_size", "view_category_size",
#         # "update_category_size", "delete_category_size", "add_category_size",
#
#         "list_category_age", "view_category_age",
#         # "update_category_age", "delete_category_age", "add_category_age",
#     ],
#     "user": [
#         # Permissões básicas de usuário
#         "register_user", "login_user",
#
#         # Permissões de leitura de espécie
#         "list_species",
#
#         # Permissões de pet (somente para seus próprios pets)
#         "add_pet", "list_pets", "update_pet", "delete_pet",
#
#         # Permissões de leitura para categorias
#         "list_category_environment", "view_category_environment",
#         "list_category_condition", "view_category_condition",
#         "list_category_purpose", "view_category_purpose",
#         "list_category_habitat", "view_category_habitat",
#         "list_category_origin", "view_category_origin",
#         "list_category_size", "view_category_size",
#         "list_category_age", "view_category_age",
#     ]
# }
#
#
# def run_permissions_seed(db: Session) -> None:
#     """
#     Executa o seed de permissões, grupos e associações.
#
#     Args:
#         db: Sessão do banco de dados
#     """
#     try:
#         logger.info("Iniciando seed de permissões e grupos")
#
#         # Criar grupos
#         group_objs = {}
#         for name in DEFAULT_GROUPS:
#             group = db.query(AuthGroup).filter_by(name=name).first()
#             if not group:
#                 group = AuthGroup(name=name)
#                 db.add(group)
#                 db.flush()  # Forçar geração de ID sem commit
#                 logger.info(f"Grupo '{name}' criado com sucesso")
#             else:
#                 logger.info(f"Grupo '{name}' já existe")
#
#             group_objs[name] = group
#
#         # Criar content types e permissões
#         permission_objs = {}
#         for ct_data in CONTENT_TYPES:
#             # Verificar se content type já existe
#             ct_obj = db.query(AuthContentType).filter_by(
#                 app_label=ct_data["app_label"], model=ct_data["model"]
#             ).first()
#
#             if not ct_obj:
#                 ct_obj = AuthContentType(app_label=ct_data["app_label"], model=ct_data["model"])
#                 db.add(ct_obj)
#                 db.flush()  # Forçar geração de ID sem commit
#                 logger.info(f"ContentType '{ct_data['app_label']}.{ct_data['model']}' criado")
#             else:
#                 logger.info(f"ContentType '{ct_data['app_label']}.{ct_data['model']}' já existe")
#
#             # Gerar codename da permissão (igual ao model)
#             codename = ct_data["model"]
#
#             # Verificar se permissão já existe
#             perm = db.query(AuthPermission).filter_by(codename=codename).first()
#             if not perm:
#                 perm = AuthPermission(
#                     name=f"Can {codename}",
#                     codename=codename,
#                     content_type_id=ct_obj.id,
#                 )
#                 db.add(perm)
#                 db.flush()  # Forçar geração de ID sem commit
#                 logger.info(f"Permissão '{codename}' criada")
#             else:
#                 logger.info(f"Permissão '{codename}' já existe")
#
#             # Armazenar referência à permissão
#             permission_objs[codename] = perm
#
#         # Associar permissões aos grupos
#         for group_name, permission_names in GROUP_PERMISSIONS.items():
#             group = group_objs[group_name]
#
#             for permission_name in permission_names:
#                 permission = permission_objs.get(permission_name)
#
#                 # Verificar se a permissão existe e ainda não está no grupo
#                 if permission and permission not in group.permissions:
#                     group.permissions.append(permission)
#                     logger.info(f"Permissão '{permission_name}' adicionada ao grupo '{group_name}'")
#                 elif permission:
#                     logger.info(f"Grupo '{group_name}' já possui a permissão '{permission_name}'")
#                 else:
#                     logger.warning(f"Permissão '{permission_name}' não encontrada!")
#
#         # Commit final para salvar todas as alterações
#         db.commit()
#         logger.info("Seed de permissões e grupos concluído com sucesso")
#
#     except Exception as e:
#         db.rollback()
#         logger.error(f"Erro ao executar seed de permissões: {str(e)}")
#         raise
#
#
# if __name__ == "__main__":
#     """
#     Ponto de entrada para execução direta do módulo.
#
#     Permite executar apenas o seed de permissões via linha de comando:
#     `python -m app.db.seeds.permissions`
#     """
#     from app.core.database import Session
#
#     # Criar sessão
#     session = Session()
#
#     try:
#         # Executar seed de permissões
#         run_permissions_seed(session)
#
#     except Exception as e:
#         session.rollback()
#         logger.error(f"Erro ao executar seed de permissões: {str(e)}")
#         raise
#
#     finally:
#         # Fechar sessão
#         session.close()
