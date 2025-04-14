# app/adapters/outbound/security/token_gerar.py

from passlib.context import CryptContext

crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenGerar:
    @classmethod
    def gerar_hash(cls, senha: str) -> str:
        """
        Gera um hash seguro usando bcrypt para a senha fornecida.
        """
        return crypt_context.hash(senha)


if __name__ == "__main__":
    import getpass

    print("🔐 Gerador de Hash Seguro para Token (HTML Forms)")
    senha = getpass.getpass("Digite a senha para gerar o hash: ")

    hash_gerado = TokenGerar.gerar_hash(senha)

    print("\n✅ Hash gerado com sucesso! Copie e cole onde necessário:\n")
    print(hash_gerado)

# Como usar:
# python app/security/token_gerar.py
