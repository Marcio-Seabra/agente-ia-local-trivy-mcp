# Experimento 1 – Linha de base

Os três modelos locais receberam o relatório do Trivy com todas as severidades e uma solicitação de cinco itens. As respostas se concentraram em oito CVEs de severidade média e baixa, que ocupam as últimas posições (4.772 a 4.779) do relatório de referência. A causa desse recorte não foi registrada; a hipótese de limite de contexto é discutida na monografia (seções 3.3 e 5.2) como inferência.

| Arquivo | Conteúdo |
|---|---|
| `referencia-trivy/trivy-fiware-orion-latest.json` | Relatório completo do Trivy 0.71.2 para `fiware/orion:latest`, gerado em 15/09/2026 (4.780 ocorrências, 4.467 CVEs distintos). É a referência usada na análise de controle e na avaliação T1. |
| `referencia-trivy/trivy-fiware-orion-latest.log` | Log da execução do Trivy que gerou o relatório acima, com o download do banco de vulnerabilidades. |
| `saidas-modelos-locais/TESTE - *.pdf` | Saídas registradas do Granite 4.2, do DeepSeek R1 e do Qwen 3.5, com o tempo de espera de cada execução (225 s, 218 s e 226 s). |
| `avaliacao/analise-controle.md` | Análise de controle usada como referência pelo avaliador. |
| `avaliacao/PROMPT_COMPARACAO.txt` | Prompt entregue ao modelo avaliador (Fable 5.1), com a solicitação original feita aos modelos locais, os critérios e a escala. |
| `avaliacao/RESULTADO_COMPARACAO.pdf` | Relatório de avaliação T1. |

Médias registradas em T1: Granite 4.2 = 2,2; DeepSeek R1 = 2,4; Qwen 3.5 = 2,4. T1 não definiu limiar de aprovação.

O código usado nesta rodada e a mensagem exata enviada aos modelos não foram preservados. O horário registrado no relatório do Trivy (22:15 de 15/09/2026) é posterior ao dos PDFs das saídas dos modelos (21:55 a 21:56 do mesmo dia, no mesmo fuso). Por isso, o arquivo é apresentado como referência da avaliação, e não como a entrada exata recebida pelos modelos.
