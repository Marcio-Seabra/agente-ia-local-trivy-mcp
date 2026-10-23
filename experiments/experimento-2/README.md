# Experimento 2 – Recorte de severidade

O escopo passou a ser as severidades HIGH e CRITICAL. As respostas dos três modelos voltaram a descrever os mesmos oito CVEs de severidade média e baixa do Experimento 1, que não pertencem a esse recorte.

| Arquivo | Conteúdo |
|---|---|
| `referencia-trivy/TRIVY_FIWARE_ORION_HIGH_CRITICAL.json` | Nova coleta do Trivy 0.71.2, de 20/09/2026, restrita a HIGH e CRITICAL (724 ocorrências, 647 CVEs distintos), usada como referência da avaliação. |
| `saidas-modelos-locais/TESTE02 - *.pdf` | Saídas registradas do Granite 4.2, do DeepSeek R1 e do Qwen 3.5, com o tempo de espera de cada execução (152 s, 219 s e 174 s). |
| `avaliacao/analise-controle.md` | Análise de controle elaborada a partir do relatório acima. |
| `avaliacao/PROMPT_COMPARACAO_TESTE02.txt` | Prompt entregue ao modelo avaliador. |
| `avaliacao/RESULTADO_COMPARACAO_TESTE02.md` e `.pdf` | Relatório de avaliação T2 (fonte em Markdown e versão em PDF). |

Médias registradas em T2: Granite 4.2 = 1,6; DeepSeek R1 = 2,4; Qwen 3.5 = 2,6. Limiar de aprovação: média igual ou superior a 7,00.

O código usado nesta rodada e a mensagem exata enviada aos modelos não foram preservados. O relatório do Trivy desta pasta foi gerado em 20/09/2026, depois dos PDFs das saídas dos modelos (19/09/2026). Por isso, ele é apresentado como referência da avaliação, e não como a entrada exata recebida pelos modelos.
