# Experimento 3 – Processamento em blocos

O protótipo em `src/version004` executou o Trivy com recorte HIGH e CRITICAL, excluiu os registros com `Status = fixed`, reduziu cada ocorrência aos campos necessários e enviou os registros ao Ollama em blocos de até 10 ocorrências, com uma solicitação de três itens por bloco. As respostas parciais foram concatenadas sem nova chamada ao modelo.

A exclusão de `fixed` foi adotada para reduzir o volume da entrada. Esses registros não eram vulnerabilidades já corrigidas na imagem, e sim vulnerabilidades com correção publicada. Por isso, os modelos locais não receberam justamente os itens com versão corrigida conhecida, o que é uma limitação do experimento.

| Arquivo | Conteúdo |
|---|---|
| `saidas-modelos-locais/TESTE03 - *.pdf` | Saídas registradas do Granite 4.2, do DeepSeek R1 e do Qwen 3.5. Cada uma informa 11 blocos analisados, 654 registros `fixed` descartados e o tempo de espera (2.143 s, 800 s e 806 s). |
| `referencia-trivy/TRIVY_FIWARE_ORION_TESTE03.json` | Coleta posterior do Trivy 0.74.0, de 19/10/2026, com todas as severidades (6.663 ocorrências), usada pelo avaliador como referência. **Não é a entrada exata dos modelos.** |
| `avaliacao/ANALISE_CONTROLE_TESTE03.md` | Análise de controle elaborada a partir da referência acima. |
| `avaliacao/PROMPT_COMPARACAO_TESTE03.txt` | Prompt entregue ao modelo avaliador, com o modelo de prompt enviado a cada bloco. |
| `avaliacao/RESULTADO_COMPARACAO_TESTE03.md` e `.pdf` | Relatório de avaliação T3, que inclui a reconstrução das 11 partes a partir das saídas. |

O relatório do Trivy usado na execução não foi preservado. A entrada efetiva foi reconstruída a partir das saídas: 109 ocorrências HIGH e CRITICAL em 11 partes (10 × 10 + 9). A coleta de referência posterior tem 118 ocorrências nesse mesmo recorte; a diferença decorre de alterações na base de vulnerabilidades entre as coletas.

Médias registradas em T3: Granite 4.2 = 6,33; DeepSeek R1 = 5,00; Qwen 3.5 = 6,67. Limiar de aprovação: média igual ou superior a 7,00.

Os gráficos de uso de recursos desta rodada estão em `figures/` (Gráficos 2 a 4 da monografia).
