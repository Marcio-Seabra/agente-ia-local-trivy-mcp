# Experimento TCC — Análise de controle (Etapas 1 e 2)

Gerado em 2026-09-15. Fonte factual: `experimento/trivy-fiware-orion-latest.json`
(log em `trivy-fiware-orion-latest.log`). As respostas dos modelos avaliados
NÃO foram consultadas para produzir este documento.

Convenção: **[Trivy]** = dado lido do relatório. **[Interpretação]** = leitura
técnica derivada, não afirmada pela ferramenta.

---

## PARTE A — EVIDÊNCIA DO TRIVY

| Item | Valor |
|---|---|
| Imagem | `fiware/orion` (tag resolvida: `fiware/orion:latest`) |
| Digest | `fiware/orion@sha256:dc29ec56888ac7d1a81bac6855fefe3cabcabcaec6bd46a3d9934bb875896edf` |
| Comando | `trivy.exe image fiware/orion --format json --output experimento/trivy-fiware-orion-latest.json --cache-dir necessarios/trivy-cache` |
| Trivy | 0.71.2 (executável local em `necessarios/trivy/`) |
| Banco de CVEs | `mirror.gcr.io/aquasec/trivy-db:2`, 113,23 MiB, atualizado na execução |
| Scanners | `vuln` + `secret` (padrão de `trivy image`) |
| Data da execução | 2026-09-15T22:15:34-03:00 |
| SO detectado | Debian 13.4 |
| Tamanho da imagem | 257.772.032 bytes, 4 camadas |
| Imagem construída em | 2026-04-14 |
| Configuração | `User=nobody`, `ExposedPorts=1026/tcp`, `Entrypoint=/usr/bin/contextBroker -fg -multiservice -disableFileLog` |
| Pacotes de linguagem | 0 (`Number of language-specific files num=0`) |
| Segredos | nenhum achado (scanner rodou; chave `Secrets` ausente) |

Observação: o digest é idêntico ao do scan de referência `fiware/orion:4.5.0`
feito em 03/09. `latest` e `4.5.0` são a mesma imagem. A diferença de contagem
(4.297 → 4.780) vem da atualização do banco de CVEs, não da imagem.

### A.1 Totais

| Métrica | Valor |
|---|---:|
| Ocorrências em `Vulnerabilities[]` | **4.780** |
| Identificadores distintos (`VulnerabilityID`) | **4.467** |
| Pacotes inventariados | 124 |
| Pacotes com pelo menos uma ocorrência | 63 |
| Com `FixedVersion` (correção disponível) | 3.575 (74,8%) |
| Sem `FixedVersion` | 1.205 (25,2%) |
| `Status=fixed` | 3.575 |
| `Status=affected` | 1.202 |
| `Status=fix_deferred` | 2 |
| `Status=will_not_fix` | 1 |
| IDs não-CVE (`TEMP-*`, Debian) | 7 |

### A.2 Distribuição por severidade (`Severity`, valor escolhido pelo Trivy)

| Severity | Ocorrências | % | Com fix | Sem fix | IDs distintos |
|---|---:|---:|---:|---:|---:|
| CRITICAL | 9 | 0,2% | 8 | 1 | 9 |
| HIGH | 737 | 15,4% | 569 | 168 | 660 |
| MEDIUM | 3.433 | 71,8% | 2.661 | 772 | 3.311 |
| LOW | 594 | 12,4% | 336 | 258 | 480 |
| UNKNOWN | 7 | 0,1% | 1 | 6 | 7 |

`SeveritySource` ausente em 3.230 registros (67,6%); `nvd` em 1.370; `debian`
em 180. Em 3.518 registros (73,6%) as fontes de `VendorSeverity` discordam
entre si. O Trivy avisou: `WARN Using severities from other vendors for some
vulnerabilities`.

### A.3 Concentração por pacote

| Pacote | Versão instalada | Ocorrências | CRIT | HIGH | MED | LOW | UNK |
|---|---|---:|---:|---:|---:|---:|---:|
| `linux-libc-dev` | 6.12.74-2 | **4.252 (88,9%)** | 4 | 621 | 3.216 | 405 | 6 |
| `curl` / `libcurl4t64` | 8.14.1-2+deb13u2 | 39 cada | 0 | 6 | 25 | 8 | 0 |
| `openssl` / `libssl3t64` / `openssl-provider-legacy` | 3.5.5-1~deb13u2 | 25 cada | 0 | 2 | 7 | 16 | 0 |
| `libc6` / `libc-bin` / `libc6-dev` / `libc-dev-bin` | 2.41-12+deb13u2 | 22 cada | 0 | 0 | 14 | 8 | 0 |
| `perl-base` | 5.40.1-6 | 17 | 3 | 5 | 8 | 1 | 0 |
| `libgnutls30t64` | 3.8.9-3+deb13u2 | 14 | 2 | 3 | 6 | 3 | 0 |
| util-linux (9 binários: `util-linux`, `mount`, `login`, `bsdutils`, `libblkid1`, `libmount1`, `libuuid1`, `libsmartcols1`, `liblastlog2-2`) | 2.41-5 | 13 cada | 0 | 7 | 4 | 2 | 0 |
| `libssh2-1t64` | 1.11.1-1 | 10 | 0 | 4 | 6 | 0 | 0 |
| `libsystemd0` / `libudev1` | 257.9-1~deb13u1 | 11 cada | 0 | 1 | 5 | 5 | 0 |
| krb5 (5 pacotes) | 1.21.3-5 | 6 cada | 0 | 2 | 0 | 4 | 0 |
| `libpcre2-8-0` | 10.46-1~deb13u1 | 7 | 0 | 2 | 2 | 3 | 0 |
| `libsqlite3-0` | 3.46.1-7+deb13u1 | 6 | 0 | 2 | 2 | 2 | 0 |

Sem `linux-libc-dev` restam **528 ocorrências**: CRITICAL 5, HIGH 116,
MEDIUM 217, LOW 189, UNKNOWN 1.

`linux-libc-dev` 6.12.74-2: 3.317 ocorrências com correção; versões corrigidas
mais frequentes: 6.12.85-1 (917), 6.12.94-1 (588), 6.12.100-1 (536),
6.12.105-1 (360), 6.12.101-1 (316). 935 sem correção.

### A.4 As 9 ocorrências CRITICAL

| CVE | Pacote | Instalada | Corrigida | Status | CVSS (fonte) | Título (Trivy) |
|---|---|---|---|---|---|---|
| CVE-2026-33845 | libgnutls30t64 | 3.8.9-3+deb13u2 | 3.8.9-3+deb13u4 | fixed | 9.1 nvd / 7.5 redhat | GnuTLS: DoS via DTLS zero-length fragment (CWE-191) |
| CVE-2026-42010 | libgnutls30t64 | 3.8.9-3+deb13u2 | 3.8.9-3+deb13u4 | fixed | 9.8 nvd / 7.1 redhat | GnuTLS: Authentication bypass via NUL character in username (RSA-PSK) |
| CVE-2026-13221 | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 | fixed | 9.1 nvd / 5.9 redhat | Perl: incorrect regex processing via large regular expressions |
| CVE-2026-42496 | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 | fixed | 9.1 nvd / 8.2 redhat | perl Archive::Tar: path traversal via crafted symlinks |
| CVE-2026-8376 | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 | fixed | 9.8 nvd / 5.7 redhat | Perl: heap buffer overflow compiling regex on 32-bit builds |
| CVE-2026-43011 | linux-libc-dev | 6.12.74-2 | 6.12.85-1 | fixed | — (ubuntu/photon = 4) | kernel: net/x25 double free of skb |
| CVE-2026-43037 | linux-libc-dev | 6.12.74-2 | 6.12.85-1 | fixed | 8.8 redhat | kernel: ip6_tunnel clear skb2->cb[] in ip4ip6_err() |
| CVE-2026-53215 | linux-libc-dev | 6.12.74-2 | 6.12.94-1 | fixed | — | kernel: net mvpp2 refill RX buffers |
| CVE-2026-43185 | linux-libc-dev | 6.12.74-2 | **—** | **affected** | — (ubuntu = 4) | kernel: ksmbd signedness bug in smb_direct_prepare_negotiation() |

Nas 5 CRITICAL de userspace, `SeveritySource=nvd`; Red Hat classifica todas
como HIGH ou MEDIUM. Nas 4 do kernel, `SeveritySource` está ausente e a nota
CRITICAL vem de Ubuntu/Photon.

### A.5 HIGH fora do kernel — 116 ocorrências, 36 CVEs distintos

| Pacote(s) | CVEs HIGH | Corrigida | Sem correção |
|---|---|---|---|
| util-linux (9 pacotes × 7) | CVE-2026-53612, -53613, -53614 → 2.41.5-0+deb13u1; CVE-2026-76642, -78408, -78409, -78410 | 3 | 4 (`affected`) |
| curl / libcurl4t64 (2 × 6) | CVE-2026-5773, -6276 → 8.14.1-2+deb13u4; CVE-2026-8286, -8458, -8927, -12064 | 2 | 4 (`affected`) |
| perl-base (5) | CVE-2026-42497, -48962, -57432, -57433 → 5.40.1-6+deb13u1; CVE-2026-9538 | 4 | 1 (`fix_deferred`) |
| libssh2-1t64 (4) | CVE-2026-55199, -55200, -7598 → 1.11.1-1+deb13u1; CVE-2026-58050 → 1.11.1-1+deb13u2 | 4 | 0 |
| libgnutls30t64 (3) | CVE-2026-33846, -3833, -42009 → 3.8.9-3+deb13u4 | 3 | 0 |
| krb5 (5 pacotes × 2) | CVE-2026-40355, -40356 → 1.21.3-5+deb13u1 | 2 | 0 |
| libpcre2-8-0 (2) | CVE-2026-86145, -89161 → 10.46-1~deb13u2 | 2 | 0 |
| libsqlite3-0 (2) | CVE-2026-11822, -11824 → 3.46.1-7+deb13u2 (FTS5, execução de código) | 2 | 0 |
| openssl (3 pacotes × 2) | CVE-2026-45447 → 3.5.6-1~deb13u2 (UAF em PKCS7_verify); CVE-2026-14456 → 3.5.7-1~deb13u2 (QUIC DoS) | 2 | 0 |
| gzip (1) | CVE-2026-41992 → 1.13-1+deb13u1 | 1 | 0 |
| libcap2 (1) | CVE-2026-4878 → 1:2.75-10+deb13u1 | 1 | 0 |
| libnghttp2-14 (1) | CVE-2026-27135 → 1.64.0-1.1+deb13u1 | 1 | 0 |
| libacl1 (1) | CVE-2026-54369 | 0 | 1 |
| libsystemd0 / libudev1 (2 × 1) | CVE-2026-16742 (systemd-homed) | 0 | 1 |
| ncurses (3 pacotes × 1) | CVE-2025-69720 | 0 | 1 |

---

## PARTE B — ANÁLISE DE CONTROLE

Resposta ao prompt: "Forneça uma análise de segurança contendo: 1. Resumo da
análise 2. Vulnerabilidades encontradas 3. Níveis de severidade 4. Principais
riscos 5. Recomendações de correção. Responda em português."

### 1. Resumo da análise

**[Trivy]** A imagem `fiware/orion:latest` (digest `dc29ec56…`, Debian 13.4,
124 pacotes do SO, sem pacotes de linguagem, sem segredos detectados) apresenta
**4.780 ocorrências de vulnerabilidade**, correspondentes a **4.467 CVEs
distintos**, em 63 pacotes. Distribuição: 9 CRITICAL, 737 HIGH, 3.433 MEDIUM,
594 LOW, 7 UNKNOWN. 3.575 ocorrências (74,8%) têm versão corrigida disponível
no Debian 13.

**[Interpretação]** O número bruto superestima a exposição real. **88,9% das
ocorrências (4.252) pertencem a um único pacote, `linux-libc-dev`**, que
contém os cabeçalhos do kernel Linux para compilação. Um container não executa
o kernel da imagem, e sim o do host. Portanto essas 4.252 entradas descrevem
falhas de um kernel que **não roda neste container** e não são exploráveis
através dele. A presença de `linux-libc-dev`, `libc6-dev` e `libgcrypt20-dev`
indica que dependências de compilação ficaram na imagem final.

Descontado o kernel, o conjunto relevante é de **528 ocorrências**: 5 CRITICAL,
116 HIGH, 217 MEDIUM, 189 LOW, 1 UNKNOWN. É sobre esse conjunto que a análise
de risco abaixo se concentra.

A imagem foi construída em abril de 2026 e a base Debian não foi atualizada
desde então; a maior parte das correções já está publicada pelo Debian.

### 2. Vulnerabilidades encontradas

Agrupadas por componente (dados **[Trivy]**; comentários **[Interpretação]**).

**a) GnuTLS 3.8.9-3+deb13u2 (`libgnutls30t64`) — 2 CRITICAL, 3 HIGH, 6 MEDIUM, 3 LOW; todas corrigidas em 3.8.9-3+deb13u4.**
CVE-2026-42010 (bypass de autenticação RSA-PSK via caractere NUL, CVSS 9.8 NVD),
CVE-2026-33845 (leitura fora dos limites em DTLS, 9.1 NVD), CVE-2026-33846 e
CVE-2026-42009 (DoS em DTLS), CVE-2026-3833 (bypass de nameConstraints).
[Interpretação] O Orion não usa GnuTLS diretamente; a biblioteca chega via
dependências (por exemplo OpenLDAP no Debian). RSA-PSK e DTLS não são
configurações típicas do Orion. Exposição indireta e baixa, mas a correção
é trivial.

**b) Perl 5.40.1-6 (`perl-base`) — 3 CRITICAL, 5 HIGH, 8 MEDIUM, 1 LOW; 16 de 17 corrigidas em 5.40.1-6+deb13u1.**
CVE-2026-42496 (Archive::Tar, path traversal por symlink, 9.1 NVD),
CVE-2026-13221 (regex incorreta, 9.1), CVE-2026-8376 (heap overflow em regex,
**apenas builds 32-bit**, 9.8), CVE-2026-48962 (IO::Compress, execução de
código), CVE-2026-57432/57433 (pack/unpack, Storable). CVE-2026-9538
(Archive::Tar DoS) está `fix_deferred`.
[Interpretação] A imagem é amd64, logo CVE-2026-8376 não se aplica. `perl-base`
é dependência do sistema Debian; o Orion (C++) não executa Perl em runtime.
Risco prático baixo, exceto se scripts Perl processarem entrada externa, o que
não ocorre no fluxo normal do Context Broker.

**c) curl / libcurl 8.14.1-2+deb13u2 — 6 HIGH, 25 MEDIUM, 8 LOW por pacote; 2 dos 6 HIGH corrigidos em 8.14.1-2+deb13u4.**
Corrigidos: CVE-2026-5773 (reuso indevido de conexão SMB), CVE-2026-6276
(vazamento de cookie em reuso de conexão). Sem correção (`affected`):
CVE-2026-8286 (conexão estabelecida com configuração TLS divergente, 8.1),
CVE-2026-8458 (reuso não autorizado de conexão, 8.1 RH), CVE-2026-8927 (estado
de autenticação de proxy não limpo, 9.1 julia / 7.5 RH), CVE-2026-12064
(bypass de verificação de host SSH em SFTP/SCP).
[Interpretação] **Este é o componente mais relevante para o Orion.** O Context
Broker usa libcurl para enviar notificações HTTP/HTTPS de subscrições a
endpoints configurados pelos usuários da API, frequentemente com TLS e às
vezes via proxy. Falhas de reuso de conexão e de estado TLS/proxy afetam
exatamente esse caminho. Já CVE-2026-12064 (SFTP/SCP) e CVE-2026-5773 (SMB)
são inaplicáveis ao uso do Orion.

**d) OpenSSL 3.5.5-1~deb13u2 (`libssl3t64`, `openssl`, `openssl-provider-legacy`) — 2 HIGH, 7 MEDIUM, 16 LOW; HIGH corrigidas.**
CVE-2026-45447 (use-after-free em `PKCS7_verify`, corrigida em 3.5.6-1~deb13u2)
e CVE-2026-14456 (DoS em servidor QUIC, corrigida em 3.5.7-1~deb13u2).
[Interpretação] OpenSSL é a pilha TLS do libcurl no Debian e, portanto, do
Orion nas notificações HTTPS. QUIC não é usado; PKCS7 só se algum componente
verificar assinaturas CMS. Exposição moderada por ser biblioteca central.

**e) util-linux 2.41-5 (9 pacotes binários) — 7 HIGH, 4 MEDIUM, 2 LOW cada; 3 HIGH corrigidas em 2.41.5-0+deb13u1, 4 `affected`.**
TOCTOU e bypass de `nosuid`/`noexec` em `mount(8)` SUID (CVE-2026-53612/13/14),
falhas em X-mount e `nsenter` (CVE-2026-76642, -78408, -78409, -78410).
[Interpretação] A mesma CVE aparece 9 vezes porque nove pacotes derivam do
mesmo fonte; são 13 CVEs, não 117. Todas exigem execução local de `mount` ou
`nsenter` com privilégio. O container roda como `nobody` sem `CAP_SYS_ADMIN`,
então o vetor não existe sem um comprometimento prévio.

**f) libssh2 1.11.1-1 — 4 HIGH, 6 MEDIUM; todas corrigidas (1.11.1-1+deb13u1 / u2).**
Overflows e DoS no cliente SSH (CVE-2026-7598, -55199, -55200, -58050).
[Interpretação] Dependência de libcurl para SFTP/SCP; o Orion não usa esses
esquemas. Exposição nula em uso normal, correção disponível.

**g) MIT Kerberos 1.21.3-5 (5 pacotes) — 2 HIGH cada; corrigidas em 1.21.3-5+deb13u1.**
CVE-2026-40355 e -40356 (DoS em NegoEx). [Interpretação] Dependência transitiva
de libcurl/OpenLDAP; sem uso de GSSAPI no Orion, sem vetor.

**h) Bibliotecas de parsing: PCRE2 10.46-1~deb13u1 (CVE-2026-86145 escrita fora dos limites com execução de código, CVE-2026-89161 em JIT; corrigidas em 10.46-1~deb13u2), SQLite 3.46.1-7+deb13u1 (CVE-2026-11822/11824 execução de código via FTS5; corrigidas em 3.46.1-7+deb13u2).**
[Interpretação] O Orion persiste em MongoDB, não em SQLite; PCRE2 pode ser
usado por bibliotecas do sistema. Exposição baixa, correção disponível.

**i) glibc 2.41-12+deb13u2 — 14 MEDIUM, 8 LOW em 4 pacotes.** Nenhuma HIGH ou
CRITICAL. [Interpretação] Biblioteca base de todo o processo; acompanhar
atualizações regulares.

**j) Sem correção disponível, fora do kernel (HIGH):** libacl1 (CVE-2026-54369,
escalada local via symlink), systemd/udev (CVE-2026-16742, systemd-homed,
não presente em container), ncurses (CVE-2025-69720, overflow em terminal).
[Interpretação] Todas locais; irrelevantes para um serviço de rede sem shell
interativo.

**k) linux-libc-dev 6.12.74-2 — 4.252 ocorrências, 4 CRITICAL.** Ver §1:
cabeçalhos, não kernel em execução. A CRITICAL sem correção
(CVE-2026-43185, ksmbd) refere-se a um servidor SMB no kernel, ausente aqui.

### 3. Níveis de severidade

**[Trivy]** Tabela A.2. `Severity` é a severidade escolhida pelo Trivy; em
73,6% dos registros os fornecedores discordam entre si, e em 67,6% o campo
`SeveritySource` está ausente. Nas 5 CRITICAL de userspace a fonte é o NVD,
enquanto a Red Hat as classifica como HIGH (7.1 a 8.2) ou MEDIUM (5.7 a 5.9).

**[Interpretação]** Recomenda-se ler a severidade em três camadas:

| Camada | Ocorrências | Leitura |
|---|---:|---|
| Total reportado | 4.780 | Número bruto; inflado por cabeçalhos do kernel e por duplicação entre binários do mesmo fonte |
| Fora do kernel | 528 (5 CRIT, 116 HIGH) | Software que de fato existe no processo ou na imagem |
| Com vetor plausível no Orion | ~50 CVEs distintos em curl, OpenSSL, GnuTLS, glibc | Onde a exposição de rede do serviço encontra a falha |

A severidade "CRITICAL" do NVD para os casos de Perl e GnuTLS reflete o pior
cenário genérico; no contexto deste container (amd64, sem RSA-PSK/DTLS, sem
Perl em runtime) o risco efetivo é menor do que o rótulo sugere. O inverso vale
para os HIGH de libcurl sem correção, que são os mais próximos do caminho de
execução real.

### 4. Principais riscos

**[Interpretação]**, ordenados por proximidade ao vetor de ataque do Orion
(serviço HTTP na porta 1026 que envia notificações HTTP/HTTPS de saída):

1. **Notificações de subscrição via libcurl (HIGH, 4 sem correção).**
   Um endpoint de notificação malicioso ou um proxy controlado pelo atacante
   pode explorar CVE-2026-8286, -8458 e -8927 para induzir reuso indevido de
   conexão, degradar a configuração TLS ou vazar credenciais de proxy entre
   destinos. Em multi-tenant (`-multiservice`), isso pode cruzar dados de
   tenants diferentes. É o risco mais concreto do relatório.
2. **Pilha TLS (OpenSSL/GnuTLS).** Use-after-free em PKCS7 e falhas de DTLS
   e nameConstraints. Vetor indireto, mas as bibliotecas estão no processo e
   correções existem para todas.
3. **Bibliotecas de parsing com execução de código (PCRE2, SQLite, gzip,
   libssh2).** Só exploráveis se dados externos chegarem a essas bibliotecas;
   no Orion isso é improvável, mas a superfície existe e o custo de corrigir é
   zero (atualização do Debian).
4. **Escalada local (util-linux, libcap2, libacl1, ncurses).** Só relevantes
   após comprometimento inicial do processo. Mitigadas por `User=nobody` e
   ausência de capabilities; ainda assim, `mount` e `nsenter` SUID não
   deveriam existir em uma imagem de serviço.
5. **Ruído operacional (linux-libc-dev, 89% do relatório).** Não é um risco
   de exploração, mas é um risco de gestão: mascara os achados relevantes e
   consome tempo de triagem.
6. **Ausência de segredos e de pacotes de linguagem** [Trivy] são pontos
   positivos: não há credenciais embutidas nem dependências npm/pip
   vulneráveis.

### 5. Recomendações de correção

**[Interpretação]**, com base nos dados de `FixedVersion` **[Trivy]**:

1. **Reconstruir a imagem sobre Debian 13 atualizado** (`apt-get update &&
   apt-get upgrade`, ou reconstruir a partir da base `debian:13` atual). Isso
   resolve de uma vez as 3.575 ocorrências com correção, incluindo 8 das 9
   CRITICAL e 569 dos 737 HIGH. Versões-alvo confirmadas pelo Trivy:
   `libgnutls30t64 3.8.9-3+deb13u4`, `perl-base 5.40.1-6+deb13u1`,
   `curl/libcurl4t64 8.14.1-2+deb13u4`, `libssl3t64 3.5.7-1~deb13u2`,
   `util-linux 2.41.5-0+deb13u1`, `libssh2-1t64 1.11.1-1+deb13u2`,
   `libpcre2-8-0 10.46-1~deb13u2`, `libsqlite3-0 3.46.1-7+deb13u2`,
   `krb5 1.21.3-5+deb13u1`.
2. **Remover pacotes de desenvolvimento da imagem final**: `linux-libc-dev`,
   `libc6-dev`, `libc-dev-bin`, `libgcrypt20-dev`. Usar build multi-stage
   para que apenas o binário `contextBroker` e suas bibliotecas de runtime
   permaneçam. Elimina 4.252 ocorrências (89%) que não representam risco real
   e torna o relatório utilizável.
3. **Tratar as 4 HIGH de libcurl sem correção** (CVE-2026-8286, -8458, -8927,
   -12064) por mitigação até o Debian publicar o patch: restringir endpoints de
   notificação a hosts confiáveis (ACL/egress), evitar proxies de saída
   compartilhados entre tenants, forçar HTTPS com validação de certificado,
   e acompanhar o Debian Security Tracker para esses IDs.
4. **Reduzir a superfície do SO**: remover `mount`, `login`, `passwd`,
   `perl-base` (se não for dependência dura), `bash-completion`, `apt` em
   imagem de produção; considerar base `debian:13-slim` ou distroless.
   Manter `User=nobody` e executar com `--cap-drop=ALL` e filesystem
   somente-leitura, o que neutraliza a classe de escalada local.
5. **Integrar o Trivy ao pipeline de build** com `--ignore-unfixed` para a
   triagem diária e um segundo passe completo semanal, reconhecendo que o
   banco de CVEs muda: esta mesma imagem passou de 4.297 para 4.780
   ocorrências em 12 dias sem mudar um byte.
6. **Registrar o digest, a data e a versão do Trivy** em cada relatório
   arquivado, para que comparações futuras sejam auditáveis.

