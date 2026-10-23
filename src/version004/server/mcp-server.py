import json
import requests

from fastmcp import FastMCP
from tools.trivy_tools003 import scan_image, trivy_version


mcp = FastMCP("Trivy MCP Server")

OLLAMA_URL = "http://localhost:11434/api/generate"
#OLLAMA_MODEL = "qwen3.5"
OLLAMA_MODEL = "deepseek-r1:8b"
#OLLAMA_MODEL = "granite4.2"

# Quantidade máxima de vulnerabilidades enviadas ao Ollama em cada parte.
VULNERABILITIES_PER_CHUNK = 5

# Tempo máximo de espera por resposta do Ollama, em segundos.
OLLAMA_TIMEOUT = 3600


def _call_ollama(prompt: str) -> str:
    """Envia um prompt ao Ollama e retorna a resposta textual."""
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=OLLAMA_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise RuntimeError(f"Erro ao consultar o Ollama: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("O Ollama retornou uma resposta JSON inválida.") from exc

    answer = payload.get("response")
    if not isinstance(answer, str) or not answer.strip():
        error = payload.get("error", "resposta vazia ou ausente")
        raise RuntimeError(f"Não foi possível obter a análise do Ollama: {error}")

    return answer.strip()


def _prepare_report(report: dict) -> tuple[list[dict], int]:
    """
    Mantém apenas os dados úteis para interpretar vulnerabilidades.
    O filtro de severidade não é repetido aqui, pois já é feito pelo Trivy.
    Vulnerabilidades com status FIXED são descartadas.
    """
    prepared_results = []
    discarded_fixed = 0

    # Campos selecionados para análise. Campos extensos ou pouco úteis
    # para a interpretação foram omitidos para reduzir o contexto enviado.
    useful_fields = (
        "VulnerabilityID",
        "PkgName",
        "InstalledVersion",
        "FixedVersion",
        "Severity",
        "Title",
        "Description",
        "PrimaryURL",
    )

    for result in report.get("Results") or []:
        vulnerabilities = []

        for vulnerability in result.get("Vulnerabilities") or []:
            status = str(vulnerability.get("Status", "")).strip().upper()
            if status == "FIXED":
                discarded_fixed += 1
                continue

            reduced = {
                field: vulnerability[field]
                for field in useful_fields
                if vulnerability.get(field) not in (None, "")
            }
            if reduced:
                vulnerabilities.append(reduced)

        if vulnerabilities:
            prepared_results.append(
                {
                    "Target": result.get("Target", "Alvo não informado"),
                    "Type": result.get("Type", "Tipo não informado"),
                    "Vulnerabilities": vulnerabilities,
                }
            )

    return prepared_results, discarded_fixed


def _make_chunks(results: list[dict]) -> list[list[dict]]:
    """Divide as vulnerabilidades em partes sem perder o alvo de cada uma."""
    chunks = []
    current_chunk = []
    current_count = 0

    for result in results:
        target = result.get("Target", "Alvo não informado")
        result_type = result.get("Type", "Tipo não informado")

        for vulnerability in result["Vulnerabilities"]:
            if current_count >= VULNERABILITIES_PER_CHUNK:
                chunks.append(current_chunk)
                current_chunk = []
                current_count = 0

            # Cada item do bloco carrega o alvo e o tipo para manter contexto.
            current_chunk.append(
                {
                    "Target": target,
                    "Type": result_type,
                    "Vulnerability": vulnerability,
                }
            )
            current_count += 1

    if current_chunk:
        chunks.append(current_chunk)

    return chunks

@mcp.tool()
def get_trivy_version() -> str:
    """Retorna a versão instalada do Trivy."""
    return trivy_version()


@mcp.tool()
def scan_summary(image: str) -> dict:
    """Retorna uma contagem das vulnerabilidades presentes no relatório do Trivy."""
    report = scan_image(image)
    critical = 0
    high = 0

    for result in report.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            status = str(vulnerability.get("Status", "")).strip().upper()
            if status == "FIXED":
                continue

            severity = str(vulnerability.get("Severity", "")).upper()
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1

    return {"critical": critical, "high": high}


@mcp.tool()
def analyze_container(image: str) -> str:
    """
    Analisa uma imagem Docker com o Trivy e o Ollama.
    O relatório é reduzido, dividido em blocos e analisado sequencialmente.
    A consolidação final é feita via código para poupar VRAM.
    """
    report = scan_image(image)
    results, discarded_fixed = _prepare_report(report)

    chunks = _make_chunks(results)
    if not chunks:
        return (
            f"Análise da imagem: {image}\n\n"
            "O Trivy não retornou vulnerabilidades HIGH ou CRITICAL pendentes "
            "de análise após a remoção dos itens com status FIXED."
        )

    partial_analyses = []

    for index, chunk in enumerate(chunks, start=1):
        chunk_json = json.dumps(chunk, ensure_ascii=False, indent=2)

        prompt = f"""
Você é um assistente de análise de segurança. Analise somente os dados abaixo.
Imagem: {image} (Parte {index} de {len(chunks)})

{chunk_json}

Produza uma análise direta em português contendo:
- Vulnerabilidades relevantes (ID e Pacote).
- Impacto provável.
- Recomendações de correção práticas.
Seja conciso e direto ao ponto.
"""
        # A API /generate do Ollama já trata isso como um contexto isolado.
        partial_answer = _call_ollama(prompt)
        partial_analyses.append(
            f"### Parte {index} de {len(chunks)}\n{partial_answer}"
        )

    # Compilação nativa em Python (Não repassa ao Ollama)
    compiled_text = "\n\n---\n\n".join(partial_analyses)

    return (
        f"# Relatório de Segurança — {image}\n\n"
        f"**Resumo da Varredura:**\n"
        f"- Blocos analisados: {len(chunks)}\n"
        f"- Vulnerabilidades descartadas (FIXED): {discarded_fixed}\n\n"
        f"---\n\n"
        f"## Análises Detalhadas\n\n"
        f"{compiled_text}"
    )
if __name__ == "__main__":
    #Comunicação web
    #mcp.run(transport="http", port=8000)
    #comunicação terminal CLI
    mcp.run()