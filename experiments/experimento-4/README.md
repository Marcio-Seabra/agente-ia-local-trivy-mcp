# Experimento 4 – Referência complementar em nuvem

O GPT-6 Astra, em modo de raciocínio alto, recebeu o conjunto de 832 ocorrências HIGH e CRITICAL e gerou a resposta G4. O Fable 5.1 avaliou essa resposta e reavaliou os relatórios dos modelos locais do Experimento 3. Não houve nova execução dos modelos locais.

| Arquivo | Conteúdo |
|---|---|
| `entrada-trivy/TRIVY_FIWARE_ORION_HIGH_CRITICAL_TESTE04.json` | J4: as 832 ocorrências HIGH e CRITICAL da coleta do Trivy 0.74.0 de 19/10/2026. Tem o mesmo identificador de relatório (`ReportID`) e a mesma data da referência do Experimento 3. |
| `resposta-nuvem/TESTE04 - GPT-6-astra-alto.pdf` | G4: resposta gerada pelo GPT-6 Astra. |
| `avaliacao/PROMPT_COMPARACAO_TESTE04.txt` | Prompt entregue ao modelo avaliador. |
| `avaliacao/RESULTADO_COMPARACAO_TESTE04.md` e `.pdf` | Relatório de avaliação T4. |

As saídas dos modelos locais avaliadas nesta rodada são as do Experimento 3 e não foram duplicadas aqui (ver `../experimento-3/saidas-modelos-locais/`).

Médias registradas em T4: Granite 4.2 = 6,00; DeepSeek R1 = 5,33; Qwen 3.5 = 6,67; GPT-6 Astra = 8,67.

Esta comparação não é controlada: o modelo em nuvem recebeu uma entrada mais ampla, com versões de correção e metadados, enquanto os modelos locais haviam recebido blocos sem essas versões. O texto exato entregue ao GPT-6 Astra não foi preservado.
