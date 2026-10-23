import json
import subprocess
from pathlib import Path

# Caminho fixo do executável do Trivy no ambiente de desenvolvimento; ajuste-o ao ambiente local.
TRIVY_PATH = r"D:\Projeto\testes-gpt\server\trivy\trivy.exe"


# Ajuste para o caminho onde o Trivy está instalado.
# Se o trivy estiver no PATH, use apenas:
# TRIVY_PATH = "trivy"


def scan_image(image: str) -> dict:

    command = [
        TRIVY_PATH,
        "image",
        "--severity",
        "HIGH,CRITICAL",
        "-f",
        "json",
        image
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True
        )

        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:

        raise RuntimeError(
            f"Erro ao executar Trivy:\n{e.stderr}"
        )

    except json.JSONDecodeError:

        raise RuntimeError(
            "O Trivy retornou um resultado inválido."
        )
    
def trivy_version() -> str:

    result = subprocess.run(
        ["trivy", "--version"],
        capture_output=True,
        text=True
    )

    return result.stdout