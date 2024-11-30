from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import gateway

# Certifica-te de que os diretórios estão configurados
os.makedirs("keys", exist_ok=True)
os.makedirs("certs", exist_ok=True)

def create_agent(agent_name):
    # Gerar o par de chaves do Agente
    print(f"[{agent_name}] Gerando chave privada...")
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Salvar a chave privada
    agent_private_key_path = f"keys/{agent_name}_private.pem"
    with open(agent_private_key_path, "wb") as f:
        f.write(agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"[{agent_name}] Chave privada salva em '{agent_private_key_path}'.")

    # Gerar a chave pública para o pedido de certificado
    agent_public_key = agent_key.public_key()
    agent_public_key_path = f"keys/{agent_name}_public.pem"
    with open(agent_public_key_path, "wb") as f:
        f.write(agent_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"[{agent_name}] Chave pública salva em '{agent_public_key_path}'.")

    # Solicitar certificado ao Gateway
    agent_cert_path = gateway.issue_certificate(agent_name, agent_public_key)
    print(f"[{agent_name}] Certificado recebido e salvo em '{agent_cert_path}'.")
    return agent_key, agent_public_key

# Criar agentes A, B, C, D
if __name__ == "__main__":
    agents = {}
    for agent_name in ["A", "B", "C", "D"]:
        agents[agent_name] = create_agent(agent_name)
