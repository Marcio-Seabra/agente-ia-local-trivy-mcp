# Experimento TCC — Rodada 2 — Análise de controle (HIGH e CRITICAL)

Gerado em 2026-09-20. Fonte factual: `TRIVY_FIWARE_ORION_HIGH_CRITICAL.json`,
produzido nesta mesma data pelo comando abaixo. As respostas dos modelos
locais (Granite 4.2, Qwen 3.5, DeepSeek R1) **não** foram consultadas para
produzir este documento.

Convenção: **[Trivy]** = dado lido diretamente do relatório JSON.
**[Interpretação]** = leitura técnica derivada, não afirmada pela ferramenta.

---

## PARTE A — EVIDÊNCIA DO TRIVY

| Item | Valor |
|---|---|
| Imagem | `fiware/orion` (tag resolvida: `fiware/orion:latest`) |
| Digest | `fiware/orion@sha256:dc29ec56888ac7d1a81bac6855fefe3cabcabcaec6bd46a3d9934bb875896edf` |
| ImageID | `sha256:8d8f5ae361f5a85fbab9250fa04e4c15e45f9e61f56a3f47207079d5f115cedc` |
| Comando | `.\trivy.exe image --severity HIGH,CRITICAL -f json -o TRIVY_FIWARE_ORION_HIGH_CRITICAL.json fiware/orion` |
| Trivy | 0.71.2 (executável local) |
| Banco de CVEs | `mirror.gcr.io/aquasec/trivy-db:2`, 114,86 MiB, baixado na execução |
| Scanners | `vuln` + `secret` (padrão de `trivy image`) |
| Data da execução | 2026-09-20T21:47:29-03:00 |
| SO detectado | Debian 13.4 (`debian`, os_version=13), arquitetura amd64 |
| Tamanho da imagem | 257.772.032 bytes, 4 camadas |
| Imagem construída em | 2026-04-14 (`ImageConfig.created`) |
| Versão do Orion | 4.5.0 (`ENV GIT_REV_ORION=4.5.0`), rótulo `org.opencontainers.image.title=Orion Context Broker` |
| Configuração de execução | `User=nobody`, `ExposedPorts=1026/tcp`, `Entrypoint=/usr/bin/contextBroker -fg -multiservice -disableFileLog`, `ENV CLEAN_DEV_TOOLS=1` |
| Pacotes de SO inventariados | 124 (`pkg_num=124`) |
| Pacotes de linguagem | 0 (`Number of language-specific files num=0`) |
| Segredos | nenhum achado (scanner executou; não há resultado da classe `secret`) |
| Fonte de dados de vulnerabilidade | Debian Security Tracker (`DataSource.ID=debian`) |
| Aviso emitido | `WARN Using severities from other vendors for some vulnerabilities` |

Observação: o digest é idêntico ao da rodada 1 (15/09/2026). A imagem não
mudou; o que mudou foi o filtro (`--severity HIGH,CRITICAL`) e o banco de
CVEs (atualizado em 20/09). Por isso a contagem de HIGH difere levemente da
rodada 1 (737 → 715): CVEs reclassificados ou corrigidos no tracker, não
alterações na imagem.

### A.1 Totais (somente HIGH e CRITICAL)

| Métrica | Valor |
|---|---:|
| Ocorrências em `Vulnerabilities[]` | **724** |
| Identificadores distintos (`VulnerabilityID`) | **647** |
| Pacotes binários com pelo menos uma ocorrência | 34 (de 124) |
| `Status=fixed` (correção disponível no Debian) | 579 (80,0%) |
| `Status=affected` (sem correção) | 144 (19,9%) |
| `Status=fix_deferred` | 1 (0,1%) |
| Com `FixedVersion` preenchido | 579 |

A diferença entre 724 ocorrências e 647 IDs distintos decorre de um mesmo
CVE ser contado uma vez por pacote binário afetado (por exemplo, 7 CVEs do
util-linux aparecem em 9 pacotes binários; 6 CVEs do curl aparecem em
`curl` e `libcurl4t64`).

### A.2 Distribuição por severidade

| Severity | Ocorrências | % | IDs distintos | Com fix | Sem fix | Deferred |
|---|---:|---:|---:|---:|---:|---:|
| CRITICAL | 9 | 1,2% | 9 | 8 | 1 | 0 |
| HIGH | 715 | 98,8% | 638 | 571 | 143 | 1 |
| **Total** | **724** | 100% | **647** | **579** | **144** | **1** |

`SeveritySource`: ausente em 437 registros (60,4%), `nvd` em 287 (39,6%).
Quando ausente, o Trivy usou a severidade de outro fornecedor
(`VendorSeverity`: redhat, ubuntu, photon, alma, etc.).

### A.3 Concentração por pacote

| Pacote (versão instalada) | Ocorrências | CRITICAL | HIGH | Com fix | Sem fix |
|---|---:|---:|---:|---:|---:|
| `linux-libc-dev` 6.12.74-2 | **602 (83,1%)** | 4 | 598 | 508 | 94 |
| util-linux 2.41-5 — 9 binários (`util-linux`, `mount`, `login`, `bsdutils`, `libblkid1`, `libmount1`, `libuuid1`, `libsmartcols1`, `liblastlog2-2`) | 63 (7 cada) | 0 | 63 | 27 | 36 |
| `curl` / `libcurl4t64` 8.14.1-2+deb13u2 | 12 (6 cada) | 0 | 12 | 4 | 8 |
| `perl-base` 5.40.1-6 | 8 | 3 | 5 | 7 | 1 (deferred) |
| krb5 1.21.3-5 — 5 binários (`libkrb5-3`, `libgssapi-krb5-2`, `libk5crypto3`, `libkrb5support0`, `krb5-locales`) | 10 (2 cada) | 0 | 10 | 10 | 0 |
| `libgnutls30t64` 3.8.9-3+deb13u2 | 5 | 2 | 3 | 5 | 0 |
| openssl 3.5.5-1~deb13u2 — 3 binários (`openssl`, `libssl3t64`, `openssl-provider-legacy`) | 6 (2 cada) | 0 | 6 | 6 | 0 |
| `libssh2-1t64` 1.11.1-1 | 4 | 0 | 4 | 4 | 0 |
| `libpcre2-8-0` 10.46-1~deb13u1 | 3 | 0 | 3 | 3 | 0 |
| ncurses 6.5+20250216-2 — 3 binários (`libtinfo6`, `ncurses-base`, `ncurses-bin`) | 3 (1 cada) | 0 | 3 | 0 | 3 |
| `libsqlite3-0` 3.46.1-7+deb13u1 | 2 | 0 | 2 | 2 | 0 |
| systemd 257.9-1~deb13u1 — `libsystemd0`, `libudev1` | 2 (1 cada) | 0 | 2 | 0 | 2 |
| `libcap2` 1:2.75-10+b8 | 1 | 0 | 1 | 1 | 0 |
| `libacl1` 2.3.2-2+b1 | 1 | 0 | 1 | 0 | 1 |
| `gzip` 1.13-1 | 1 | 0 | 1 | 1 | 0 |
| `libnghttp2-14` 1.64.0-1.1 | 1 | 0 | 1 | 1 | 0 |

Sem `linux-libc-dev` restam **122 ocorrências** e **45 CVEs distintos**
(5 CRITICAL, 40 HIGH), distribuídos em 33 pacotes binários. Destes, 71
ocorrências têm correção e 51 não têm (50 `affected` + 1 `fix_deferred`).

`linux-libc-dev` 6.12.74-2 [Trivy]: 508 ocorrências com correção. Versões
corrigidas mais frequentes: 6.12.85-1 (160), 6.12.94-1 (110), 6.12.100-1
(47), 6.12.96-1 (44), 6.12.105-1 (37), 6.12.101-1 (26), 6.12.86-1 (24),
6.12.95-1 (23), 6.12.88-1 (23), 6.12.90-1 (9), 6.12.107-1 (3). 94 sem
correção. Ano dos identificadores: 575 de 2026, 20 de 2025 e 7 anteriores
(CVE-2013-7445, CVE-2019-19449, CVE-2019-19814, CVE-2021-3847,
CVE-2021-3864, CVE-2024-21803, CVE-2024-58015), todos sem correção.
Subsistemas mais citados nos títulos: `net` (33), `wifi` (25), `ksmbd` (22),
`smb` (16), `netfilter` (15), `KVM` (14), `usb`/`USB` (20), `Bluetooth` (11),
`sctp` (11), `ALSA` (10). CWEs mais frequentes: CWE-416 use-after-free (155),
CWE-787 escrita fora dos limites (69), CWE-125 leitura fora dos limites (61),
CWE-415 double free (32).

### A.4 As 9 ocorrências CRITICAL

| CVE | Pacote | Instalada | Corrigida | Status | CVSS v3 (fonte) | Título (Trivy) |
|---|---|---|---|---|---|---|
| CVE-2026-42010 | libgnutls30t64 | 3.8.9-3+deb13u2 | 3.8.9-3+deb13u4 | fixed | 9.8 nvd / 7.1 redhat | GnuTLS: authentication bypass via NUL character in username (RSA-PSK) — CWE-170/626 |
| CVE-2026-33845 | libgnutls30t64 | 3.8.9-3+deb13u2 | 3.8.9-3+deb13u4 | fixed | 9.1 nvd / 7.5 redhat | GnuTLS: DoS/leitura fora dos limites via fragmento DTLS de comprimento zero — CWE-191 |
| CVE-2026-8376 | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 | fixed | 9.8 nvd / 5.7 redhat | Perl: heap buffer overflow ao compilar regex em builds de 32 bits — CWE-680 |
| CVE-2026-13221 | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 | fixed | 9.1 nvd / 5.9 redhat | Perl: processamento incorreto de regex com mais de 65535 ramos — CWE-190 |
| CVE-2026-42496 | perl-base | 5.40.1-6 | 5.40.1-6+deb13u1 | fixed | 9.1 nvd / 8.2 redhat | Perl Archive::Tar: path traversal via symlinks — CWE-59/22 |
| CVE-2026-43037 | linux-libc-dev | 6.12.74-2 | 6.12.85-1 | fixed | 8.8 redhat (sem nvd) | kernel: ip6_tunnel clear skb2->cb[] in ip4ip6_err() — CWE-787/843 |
| CVE-2026-43011 | linux-libc-dev | 6.12.74-2 | 6.12.85-1 | fixed | — (ubuntu/photon=CRITICAL) | kernel: net/x25 double free of skb — CWE-415 |
| CVE-2026-53215 | linux-libc-dev | 6.12.74-2 | 6.12.94-1 | fixed | — (ubuntu/photon=CRITICAL) | kernel: net mvpp2 refill RX buffers before XDP or skb use |
| CVE-2026-43185 | linux-libc-dev | 6.12.74-2 | **—** | **affected** | — (apenas ubuntu=CRITICAL) | kernel: ksmbd signedness bug in smb_direct_prepare_negotiation() — CWE-674 |

Nas 5 CRITICAL de espaço de usuário, `SeveritySource=nvd`; Red Hat classifica
todas como HIGH ou MEDIUM (`VendorSeverity.redhat` = 3 ou 2). Nas 4 do
kernel, `SeveritySource` está ausente e a nota CRITICAL vem de Ubuntu e/ou
Photon; CVE-2026-43185 é CRITICAL exclusivamente pela Ubuntu.

### A.5 HIGH fora do kernel — 117 ocorrências, 40 CVEs distintos

Agrupado por pacote-fonte. "Fix" indica a versão Debian que corrige.

**curl 8.14.1-2+deb13u2** (`curl`, `libcurl4t64`) — 6 CVEs, 2 com fix (8.14.1-2+deb13u4), 4 sem fix:
- CVE-2026-8286 — 8.1 redhat — conexão insegura por incompatibilidade de configuração TLS — **sem fix**
- CVE-2026-8458 — 8.1 redhat — reutilização não autorizada de conexão por erro lógico — **sem fix**
- CVE-2026-12064 — 7.5 redhat — bypass de verificação de host SSH com URLs sem esquema (SFTP/SCP) — **sem fix**
- CVE-2026-8927 — 7.5 redhat — vazamento de estado de autenticação de proxy — **sem fix**
- CVE-2026-5773 — 7.5 nvd / 6.5 redhat — transferência de arquivo errada por reutilização incorreta de conexão SMB — fix
- CVE-2026-6276 — 7.5 nvd / 3.7 redhat — vazamento de cookie ao reutilizar conexões com cabeçalho Host customizado — fix

**gnutls 3.8.9-3+deb13u2** (`libgnutls30t64`) — 3 HIGH (além das 2 CRITICAL), todas com fix (3.8.9-3+deb13u4):
- CVE-2026-33846 — 7.5 redhat — DoS por heap overflow na remontagem de fragmentos DTLS
- CVE-2026-42009 — 7.5 redhat — DoS por reordenação de pacotes DTLS
- CVE-2026-3833 — 7.4 nvd / 6.5 redhat — bypass de política por comparação case-sensitive em nameConstraints

**openssl 3.5.5-1~deb13u2** (`openssl`, `libssl3t64`, `openssl-provider-legacy`) — 2 CVEs, com fix:
- CVE-2026-45447 — 8.1 redhat — heap use-after-free em `PKCS7_verify()` — fix 3.5.6-1~deb13u2
- CVE-2026-14456 — 7.5 redhat — DoS por crescimento ilimitado de memória no servidor QUIC — fix 3.5.7-1~deb13u2

**perl 5.40.1-6** (`perl-base`) — 5 HIGH (além das 3 CRITICAL):
- CVE-2026-57432 — 8.4 nvd / 5.0 redhat — divulgação de informação por overflow em pack/unpack — fix 5.40.1-6+deb13u1
- CVE-2026-48962 — 7.8 redhat — IO::Compress: execução de código via glob de saída controlado — fix
- CVE-2026-42497 — 7.5 nvd / 6.8 redhat — Archive::Tar: modificação arbitrária de arquivo via hardlinks — fix
- CVE-2026-57433 — 7.5 redhat — Storable: DoS por overflow de inteiro na desserialização — fix
- CVE-2026-9538 — 7.5 nvd/redhat — Archive::Tar: DoS por cabeçalho tar com tamanho grande — **fix_deferred**

**libssh2 1.11.1-1** (`libssh2-1t64`) — 4 CVEs, todas com fix (1.11.1-1+deb13u1 ou +deb13u2):
- CVE-2026-7598 — **9.1 redhat** — overflow de inteiro com usuário/senha longos (classificada HIGH pelo Trivy)
- CVE-2026-55200 — 8.3 nvd / 7.1 redhat — escrita fora dos limites via `packet_length` não verificado
- CVE-2026-58050 — 7.5 nvd / 7.0 redhat — heap overflow na alocação de atributos publickey
- CVE-2026-55199 — 7.5 nvd / 5.9 redhat — DoS via mensagem `SSH_MSG_EXT_INFO`

**util-linux 2.41-5** (9 binários) — 7 CVEs, 3 com fix (2.41.5-0+deb13u1), 4 sem fix:
- CVE-2026-78408 — 7.9 redhat — `nsenter --join-cgroup` vaza autoridade de migração de cgroup — **sem fix**
- CVE-2026-76642 — 7.8 redhat — helper de mount falho ainda executa post-hooks privilegiados — **sem fix**
- CVE-2026-78410 — 7.8 redhat — bind mounts restritos não fixam a origem (redirecionamento owner/group/mode) — **sem fix**
- CVE-2026-78409 — 7.0 redhat — `X-mount.subdir` pode escapar via symlinks intermediários — **sem fix**
- CVE-2026-53612 — 7.0 redhat — TOCTOU no mount ao aplicar owner/mode pós-mount — fix
- CVE-2026-53613 — 7.0 redhat — TOCTOU no mount via troca de diretório ancestral — fix
- CVE-2026-53614 — 7.0 redhat — mount SUID permite bypass de nosuid/noexec via `LIBMOUNT_FORCE_MOUNT2` — fix

**krb5 1.21.3-5** (5 binários) — 2 CVEs, com fix (1.21.3-5+deb13u1):
- CVE-2026-40355 — 7.5 nvd / 5.9 redhat — DoS por desreferência de ponteiro nulo no mecanismo NegoEx
- CVE-2026-40356 — 7.5 nvd / 5.9 redhat — DoS por underflow de inteiro e leitura fora dos limites

**pcre2 10.46-1~deb13u1** (`libpcre2-8-0`) — 3 CVEs, com fix (10.46-1~deb13u2):
- CVE-2026-86145 — 8.2 redhat — escrita fora dos limites permite execução de código via regex maliciosa
- CVE-2026-89161 — 7.8 nvd / 7.4 redhat — corrupção de memória em `pcre2_jit_match`
- CVE-2026-89157 — 7.4 nvd / 5.7 redhat — escrita fora dos limites com padrão grande

**sqlite 3.46.1-7+deb13u1** (`libsqlite3-0`) — 2 CVEs, com fix (3.46.1-7+deb13u2):
- CVE-2026-11822 — 7.8 redhat / 8.5 v4 bitnami — execução de código via dados FTS5 maliciosos
- CVE-2026-11824 — 7.8 redhat / 8.5 v4 bitnami — heap overflow em FTS5

**systemd 257.9-1~deb13u1** (`libsystemd0`, `libudev1`) — 1 CVE, **sem fix**:
- CVE-2026-16742 — 8.8 redhat — systemd-homed: escalada local por falta de verificação de assinatura do home-record

**ncurses 6.5+20250216-2** (`libtinfo6`, `ncurses-base`, `ncurses-bin`) — 1 CVE, **sem fix**:
- CVE-2025-69720 — 7.8 nvd/redhat — buffer overflow que pode levar a execução de código

**Pacotes isolados:**
- `libcap2` — CVE-2026-4878 — 7.0 nvd / 6.7 redhat — escalada de privilégio por TOCTOU em `cap_set_file()` — fix 1:2.75-10+deb13u1
- `libacl1` — CVE-2026-54369 — 7.1 redhat — escalada por symlink traversal em funções libacl — **sem fix**
- `gzip` — CVE-2026-41992 — 7.5 nvd / 3.6 redhat — divulgação de informação por overflow na descompressão LZH — fix 1.13-1+deb13u1
- `libnghttp2-14` — CVE-2026-27135 — 7.5 redhat — DoS via frames HTTP/2 malformados após término de sessão — fix 1.64.0-1.1+deb13u1

Resumo dos 12 CVEs de espaço de usuário sem correção disponível (50 ocorrências
`affected` + 1 `fix_deferred`): 4 do curl, 4 do util-linux, 1 systemd, 1
ncurses, 1 libacl, 1 perl (deferred).

---

## PARTE B — ANÁLISE DE CONTROLE

Resposta à solicitação: "Forneça uma análise de segurança contendo: 1. Resumo
da análise; 2. Vulnerabilidades encontradas; 3. Níveis de severidade; 4.
Principais riscos; 5. Recomendações de correção."

### 1. Resumo da análise

A imagem `fiware/orion:latest` (Orion Context Broker 4.5.0, construída em
14/04/2026 sobre Debian 13.4) foi analisada pelo Trivy 0.71.2 em 20/09/2026,
com filtro de severidade HIGH e CRITICAL. O scanner encontrou **724
ocorrências** correspondentes a **647 CVEs distintos** em **34 dos 124 pacotes
de sistema operacional** inventariados. Não há dependências de linguagem
detectáveis (o binário `contextBroker` é compilado em C++ e suas bibliotecas
embutidas não são inventariadas) e nenhum segredo foi encontrado.

Três características definem o cenário:

1. **Concentração extrema em um único pacote.** `linux-libc-dev` 6.12.74-2
   (cabeçalhos do kernel Linux) responde por 602 das 724 ocorrências (83,1%),
   incluindo 4 das 9 CRITICAL. [Interpretação] Trata-se de um pacote de
   desenvolvimento que não contém código executável: os CVEs referem-se ao
   kernel em execução, que em um container é sempre o kernel do host. Esses
   602 achados não são exploráveis por meio da imagem, mas indicam que o
   processo de build deixou artefatos de compilação (`CLEAN_DEV_TOOLS=1` não
   removeu esse pacote) e inflam o relatório.

2. **Superfície real de espaço de usuário reduzida, porém relevante.**
   Excluído o kernel, restam 122 ocorrências e 45 CVEs distintos (5 CRITICAL,
   40 HIGH) em 33 pacotes. Os componentes que importam para o serviço são
   as bibliotecas de rede e criptografia usadas pelo broker para receber
   requisições NGSI e enviar notificações: **curl/libcurl** (6 CVEs, 4 sem
   correção), **OpenSSL** (2), **GnuTLS** (5, incluindo 2 CRITICAL),
   **nghttp2** (1), **libssh2** (4), **krb5** (2) e **PCRE2** (3).

3. **Alta disponibilidade de correções.** 579 ocorrências (80,0%) já têm
   versão corrigida no Debian 13; 144 (19,9%) estão `affected` sem correção e
   1 está `fix_deferred`. Das 9 CRITICAL, 8 são corrigíveis por atualização
   de pacote; a única sem correção (CVE-2026-43185, ksmbd) é do kernel.
   [Interpretação] Um simples rebuild da imagem sobre a base Debian 13
   atualizada eliminaria a maioria dos achados; a remoção de
   `linux-libc-dev` eliminaria os 602 restantes do kernel.

A imagem executa como `nobody` e expõe apenas a porta 1026/tcp, o que reduz o
impacto dos CVEs de escalada de privilégio local (util-linux, libcap, libacl,
systemd, ncurses). O risco dominante, portanto, está nos componentes de
rede/TLS alcançáveis remotamente e na obsolescência da imagem (cinco meses
sem rebuild), não na quantidade bruta de achados.

### 2. Vulnerabilidades encontradas

#### 2.1 Visão geral

| Grupo | Ocorrências | CVEs distintos | CRITICAL | HIGH | Com fix | Sem fix |
|---|---:|---:|---:|---:|---:|---:|
| Kernel (`linux-libc-dev`) | 602 | 602 | 4 | 598 | 508 | 94 |
| Espaço de usuário (33 pacotes) | 122 | 45 | 5 | 40 | 71 | 51 |
| **Total** | **724** | **647** | **9** | **715** | **579** | **145** |

#### 2.2 As nove vulnerabilidades CRITICAL

**GnuTLS 3.8.9-3+deb13u2 (`libgnutls30t64`) — 2 CRITICAL, corrigidas em 3.8.9-3+deb13u4**

- **CVE-2026-42010** (CVSS 9.8 NVD / 7.1 Red Hat). Servidores configurados
  com RSA-PSK comparam incorretamente nomes de usuário contendo caractere NUL
  com nomes truncados, permitindo **bypass de autenticação** remoto.
  [Interpretação] Só afeta serviços que usem GnuTLS como servidor TLS com
  RSA-PSK; não é o caso do Orion, que expõe HTTP simples na porta 1026.
- **CVE-2026-33845** (9.1 NVD / 7.5 Red Hat). Fragmentos DTLS de comprimento
  zero com offset não-zero provocam underflow de inteiro e leitura fora dos
  limites na remontagem do handshake: divulgação de informação ou DoS remoto.

**Perl 5.40.1-6 (`perl-base`) — 3 CRITICAL, corrigidas em 5.40.1-6+deb13u1**

- **CVE-2026-8376** (9.8 NVD / 5.7 Red Hat). Heap buffer overflow ao compilar
  expressões regulares com substring fixa repetida em builds de 32 bits.
  [Interpretação] A imagem é amd64; a condição de 32 bits não se aplica.
- **CVE-2026-13221** (9.1 NVD / 5.9 Red Hat). Alternância com mais de 65535
  ramos compilada em trie produz correspondências silenciosamente incorretas
  (campo de 16 bits).
- **CVE-2026-42496** (9.1 NVD / 8.2 Red Hat). `Archive::Tar` extrai symlinks
  com alvos controlados pelo atacante fora do diretório de extração (path
  traversal, CWE-22/59).

[Interpretação] `perl-base` é pacote *Essential* do Debian, presente por
dependência de ferramentas de sistema; o Orion não executa Perl em tempo de
execução. A exploração exige que um processo Perl processe entrada maliciosa
dentro do container.

**Kernel Linux (`linux-libc-dev` 6.12.74-2) — 4 CRITICAL**

- **CVE-2026-43037** (8.8 Red Hat) — `ip6_tunnel`: `cb[]` não limpo em
  `ip4ip6_err()`, confusão de tipo/escrita fora dos limites. Fix 6.12.85-1.
- **CVE-2026-43011** — `net/x25`: double free de skb. Fix 6.12.85-1.
- **CVE-2026-53215** — `net: mvpp2`: uso de buffer RX após devolução ao pool
  (driver de rede Marvell). Fix 6.12.94-1.
- **CVE-2026-43185** — `ksmbd`: bug de sinal em
  `smb_direct_prepare_negotiation()` (servidor SMB in-kernel). **Sem
  correção** (`affected`).

[Interpretação] Os quatro dependem de subsistemas do kernel do host (túnel
IPv6, X.25, driver Marvell, servidor SMB) que não são acionados pelo Orion e,
em geral, não estão habilitados em hosts de container. Sua presença no
relatório é consequência da inclusão dos cabeçalhos do kernel na imagem.

#### 2.3 Vulnerabilidades HIGH em componentes de rede e criptografia

Estes são os achados com maior relevância para o serviço, pois o Orion recebe
requisições HTTP na porta 1026 e envia notificações HTTP/HTTPS a endpoints
definidos nas subscrições, via libcurl.

| Componente | CVE | CVSS (redhat) | Efeito | Fix |
|---|---|---:|---|---|
| libcurl | CVE-2026-8286 | 8.1 | Conexão TLS estabelecida com configuração insegura por incompatibilidade | **não** |
| libcurl | CVE-2026-8458 | 8.1 | Reutilização não autorizada de conexão (erro lógico) | **não** |
| libcurl | CVE-2026-8927 | 7.5 | Vazamento de estado de autenticação de proxy | **não** |
| libcurl | CVE-2026-12064 | 7.5 | Bypass de verificação de host SSH (SFTP/SCP, URL sem esquema) | **não** |
| libcurl | CVE-2026-5773 | 6.5 (7.5 nvd) | Transferência errada por reutilização de conexão SMB | 8.14.1-2+deb13u4 |
| libcurl | CVE-2026-6276 | 3.7 (7.5 nvd) | Vazamento de cookie ao reutilizar conexão com Host customizado | 8.14.1-2+deb13u4 |
| OpenSSL | CVE-2026-45447 | 8.1 | Heap use-after-free em `PKCS7_verify()` | 3.5.6-1~deb13u2 |
| OpenSSL | CVE-2026-14456 | 7.5 | DoS por memória ilimitada no servidor QUIC | 3.5.7-1~deb13u2 |
| GnuTLS | CVE-2026-33846 | 7.5 | DoS por heap overflow em fragmentos DTLS | 3.8.9-3+deb13u4 |
| GnuTLS | CVE-2026-42009 | 7.5 | DoS por reordenação DTLS | 3.8.9-3+deb13u4 |
| GnuTLS | CVE-2026-3833 | 6.5 (7.4 nvd) | Bypass de política de nameConstraints (case-sensitive) | 3.8.9-3+deb13u4 |
| nghttp2 | CVE-2026-27135 | 7.5 | DoS via frames HTTP/2 malformados após fim de sessão | 1.64.0-1.1+deb13u1 |
| libssh2 | CVE-2026-7598 | **9.1** | Overflow de inteiro com usuário/senha longos | 1.11.1-1+deb13u1 |
| libssh2 | CVE-2026-55200 | 7.1 (8.3 nvd) | Escrita fora dos limites via `packet_length` | 1.11.1-1+deb13u1 |
| libssh2 | CVE-2026-58050 | 7.0 | Heap overflow em atributos publickey | 1.11.1-1+deb13u2 |
| libssh2 | CVE-2026-55199 | 5.9 (7.5 nvd) | DoS via `SSH_MSG_EXT_INFO` | 1.11.1-1+deb13u1 |
| krb5 | CVE-2026-40355 | 5.9 (7.5 nvd) | DoS por ponteiro nulo em NegoEx | 1.21.3-5+deb13u1 |
| krb5 | CVE-2026-40356 | 5.9 (7.5 nvd) | DoS por underflow/leitura fora dos limites | 1.21.3-5+deb13u1 |

[Interpretação] libssh2 e krb5 são dependências transitivas do libcurl
(suporte a SFTP/SCP e autenticação GSSAPI). O Orion não usa esses
protocolos, mas as bibliotecas são carregadas pelo processo.

#### 2.4 Vulnerabilidades HIGH em processamento de dados

| Componente | CVE | CVSS (redhat) | Efeito | Fix |
|---|---|---:|---|---|
| PCRE2 | CVE-2026-86145 | 8.2 | Escrita fora dos limites → execução de código via regex | 10.46-1~deb13u2 |
| PCRE2 | CVE-2026-89161 | 7.4 (7.8 nvd) | Corrupção de memória em `pcre2_jit_match` | 10.46-1~deb13u2 |
| PCRE2 | CVE-2026-89157 | 5.7 (7.4 nvd) | Escrita fora dos limites com padrão grande | 10.46-1~deb13u2 |
| SQLite | CVE-2026-11822 | 7.8 | Execução de código via dados FTS5 | 3.46.1-7+deb13u2 |
| SQLite | CVE-2026-11824 | 7.8 | Heap overflow em FTS5 | 3.46.1-7+deb13u2 |
| gzip | CVE-2026-41992 | 3.6 (7.5 nvd) | Divulgação de informação na descompressão LZH | 1.13-1+deb13u1 |
| Perl | CVE-2026-57432 | 5.0 (8.4 nvd) | Divulgação de informação em pack/unpack | 5.40.1-6+deb13u1 |
| Perl | CVE-2026-48962 | 7.8 | IO::Compress: execução de código via glob de saída | 5.40.1-6+deb13u1 |
| Perl | CVE-2026-42497 | 6.8 (7.5 nvd) | Archive::Tar: modificação arbitrária via hardlinks | 5.40.1-6+deb13u1 |
| Perl | CVE-2026-57433 | 7.5 | Storable: DoS na desserialização | 5.40.1-6+deb13u1 |
| Perl | CVE-2026-9538 | 7.5 | Archive::Tar: DoS por cabeçalho tar grande | **fix_deferred** |

[Interpretação] O Orion aceita padrões de expressão regular em consultas NGSI
(`idPattern`, `typePattern`). Se a implementação utilizar PCRE2 para avaliar
esses padrões, CVE-2026-86145 torna-se alcançável por entrada de API; o Trivy
não fornece essa informação de vínculo. SQLite e gzip não fazem parte do fluxo
de execução do broker.

#### 2.5 Vulnerabilidades HIGH de escalada de privilégio local

| Componente | CVE | CVSS (redhat) | Efeito | Fix |
|---|---|---:|---|---|
| util-linux (×9) | CVE-2026-78408 | 7.9 | `nsenter --join-cgroup` vaza autoridade de cgroup | **não** |
| util-linux (×9) | CVE-2026-76642 | 7.8 | Post-hooks privilegiados após falha do helper de mount | **não** |
| util-linux (×9) | CVE-2026-78410 | 7.8 | Bind mount restrito não fixa origem | **não** |
| util-linux (×9) | CVE-2026-78409 | 7.0 | Escape via symlinks em `X-mount.subdir` | **não** |
| util-linux (×9) | CVE-2026-53612/53613 | 7.0 | TOCTOU no mount | 2.41.5-0+deb13u1 |
| util-linux (×9) | CVE-2026-53614 | 7.0 | Bypass nosuid/noexec via `LIBMOUNT_FORCE_MOUNT2` | 2.41.5-0+deb13u1 |
| systemd (×2) | CVE-2026-16742 | 8.8 | systemd-homed: escalada local | **não** |
| ncurses (×3) | CVE-2025-69720 | 7.8 | Buffer overflow → execução de código | **não** |
| libcap2 | CVE-2026-4878 | 6.7 (7.0 nvd) | TOCTOU em `cap_set_file()` | 1:2.75-10+deb13u1 |
| libacl1 | CVE-2026-54369 | 7.1 | Symlink traversal em libacl | **não** |

[Interpretação] Todos exigem execução prévia de código no container e, na
maioria, um binário SUID ou o daemon systemd-homed, ausentes em um container
que roda como `nobody` sem systemd. São vetores de segunda etapa.

#### 2.6 Vulnerabilidades HIGH do kernel (598 ocorrências)

Os 598 HIGH de `linux-libc-dev` seguem o padrão dos CRITICAL: correções de
memória (use-after-free, escrita/leitura fora dos limites, double free) em
subsistemas variados: rede (`net`, `netfilter`, `sctp`, `ipv6`, `wifi`,
`Bluetooth`), servidores in-kernel (`ksmbd`, `smb`, `nfsd`), virtualização
(`KVM`), drivers (`usb`, `ALSA`, `media`, `drm/amd`, `scsi`, `spi`), `bpf` e
sistemas de arquivos (`f2fs`). 505 têm correção em versões 6.12.85-1 a
6.12.107-1; 93 estão sem correção. Os 24 com CVSS Red Hat ≥ 8.0 incluem
CVE-2026-68457 (ksmbd, 9.1), CVE-2026-52924 (sctp, 8.8), CVE-2026-53360 (KVM
SEV, 8.8), CVE-2026-64268 (RDMA/siw, 8.8) e CVE-2026-68159 (libceph, 8.8).

[Interpretação] Nenhum desses CVEs é corrigível dentro da imagem; o pacote
contém apenas cabeçalhos. A mitigação real é manter o kernel do host
atualizado. Do ponto de vista da imagem, o achado correto é "pacote de
desenvolvimento desnecessário presente".

### 3. Níveis de severidade

#### 3.1 Distribuição

| Severidade | Ocorrências | % | CVEs distintos | Corrigíveis |
|---|---:|---:|---:|---:|
| CRITICAL | 9 | 1,2% | 9 | 8 (88,9%) |
| HIGH | 715 | 98,8% | 638 | 571 (79,9%) |

Sem o kernel: CRITICAL 5, HIGH 117 (40 CVEs distintos); 71 corrigíveis.

#### 3.2 Como o Trivy atribuiu as severidades

O Trivy usa o campo `Severity` a partir de uma cadeia de fontes: NVD quando
disponível (`SeveritySource=nvd`, 287 registros, 39,6%) e, na ausência, a
classificação de outros fornecedores (`VendorSeverity`), o que ocorreu em 437
registros (60,4%) e motivou o aviso `Using severities from other vendors`.

Consequências observáveis nos dados:

- **Divergência NVD × Red Hat nas CRITICAL de espaço de usuário.** As 5
  CRITICAL de GnuTLS e Perl são CRITICAL pela NVD (9.1–9.8) mas HIGH ou
  MEDIUM pela Red Hat (5.7–8.2). CVE-2026-8376 (Perl, 9.8 NVD) recebe 5.7 da
  Red Hat porque só afeta builds de 32 bits. CVE-2026-13221 (9.1 NVD) recebe
  5.9. [Interpretação] A pontuação NVD reflete o pior caso teórico; a da Red
  Hat considera o contexto de distribuição. Para priorização em Debian amd64,
  a segunda é mais fiel.
- **CRITICAL do kernel sem pontuação NVD.** CVE-2026-43011, CVE-2026-53215 e
  CVE-2026-43185 não têm CVSS da NVD nem da Red Hat; a rotulagem CRITICAL vem
  de Ubuntu e Photon. CVE-2026-43185 é CRITICAL apenas pela Ubuntu.
  [Interpretação] São classificações provisórias de baixa confiança.
- **HIGH com pontuação superior às CRITICAL.** CVE-2026-7598 (libssh2) tem
  9.1 pela Red Hat e CVE-2026-68457 (ksmbd) também 9.1, mas ambas são HIGH
  no Trivy por ausência de avaliação NVD. CVE-2026-16742 (systemd, 8.8) e
  CVE-2026-45447 (OpenSSL, 8.1) superam várias CRITICAL na escala Red Hat.
- **HIGH com pontuação baixa.** CVE-2026-6276 (curl, 3.7 Red Hat) e
  CVE-2026-41992 (gzip, 3.6 Red Hat) são HIGH apenas pela NVD (7.5).

#### 3.3 Interpretação da severidade para este contexto

[Interpretação] A severidade do Trivy é um atributo do CVE, não da imagem.
Aplicando três filtros de contexto (pacote executável? componente usado pelo
serviço? alcançável remotamente?), a ordenação prática fica:

1. **Prioridade máxima**: libcurl (4 CVEs HIGH sem correção, 8.1 e 7.5),
   OpenSSL CVE-2026-45447 (8.1), GnuTLS (5 CVEs, incluindo o bypass de
   autenticação 9.8), nghttp2 (7.5), PCRE2 CVE-2026-86145 (8.2) — todos em
   bibliotecas carregadas pelo processo do broker e expostas a dados de
   rede.
2. **Prioridade alta**: libssh2 e krb5 (carregados por libcurl, protocolos não
   usados), SQLite, Perl (inclusive as 3 CRITICAL), gzip — corrigíveis com
   `apt upgrade`.
3. **Prioridade média**: util-linux, systemd, ncurses, libcap, libacl —
   escalada local, mitigada por `User=nobody`.
4. **Fora do escopo da imagem**: 602 CVEs de `linux-libc-dev` — resolver no
   host e remover o pacote da imagem.

### 4. Principais riscos

**R1 — Comprometimento do canal de notificações (libcurl, sem correção).**
O Orion envia notificações HTTP/HTTPS para URLs definidas por quem cria
subscrições. CVE-2026-8286 (configuração TLS insegura) e CVE-2026-8458
(reutilização indevida de conexão) permitem que uma conexão seja estabelecida
com parâmetros mais fracos que os esperados ou reaproveitada para destino
errado; CVE-2026-8927 pode vazar credenciais de proxy. Como o atacante que
controla uma subscrição controla o servidor de destino, ele pode explorar
essas falhas do lado servidor. Nenhuma das quatro tem correção no Debian 13
no momento do scan. [Interpretação] Risco mais concreto do relatório:
componente em uso, entrada controlada por terceiros, sem patch.

**R2 — Negação de serviço e corrupção de memória na pilha TLS/HTTP.**
OpenSSL CVE-2026-45447 (UAF em `PKCS7_verify`, 8.1), GnuTLS CVE-2026-33845/
33846/42009 (DTLS), nghttp2 CVE-2026-27135 (HTTP/2) e OpenSSL CVE-2026-14456
(QUIC). [Interpretação] O Orion usa HTTP/1.1 sobre TCP; DTLS e QUIC não são
acionados, e o HTTP/2 só se um endpoint de notificação negociar. A exposição
efetiva é menor que a nominal, mas as bibliotecas estão carregadas e todas
têm correção disponível.

**R3 — Execução de código por expressão regular (PCRE2).** CVE-2026-86145
(8.2) permite escrita fora dos limites a partir de uma regex maliciosa. Se o
broker delegar `idPattern`/`typePattern` ao PCRE2, uma consulta NGSI
maliciosa torna-se um vetor de execução remota de código com privilégios de
`nobody`. Corrigível.

**R4 — Bypass de autenticação em GnuTLS (CVE-2026-42010, 9.8).** Único
CRITICAL com impacto de integridade/autenticação em componente de rede.
[Interpretação] Requer servidor GnuTLS com RSA-PSK, configuração ausente no
Orion; risco latente para qualquer outro processo da imagem que use GnuTLS
como servidor. Corrigível.

**R5 — Escalada local após comprometimento inicial.** 4 CVEs de util-linux
sem correção (7.0–7.9), systemd-homed 8.8 sem correção, ncurses 7.8 sem
correção, libacl 7.1 sem correção, libcap 7.0. [Interpretação] Exigem código
já em execução no container; `User=nobody` e ausência de SUID/systemd reduzem
a viabilidade, mas não a eliminam se o container for executado com
capacidades adicionais ou como root.

**R6 — Risco residual não corrigível pela imagem.** 145 ocorrências sem
correção (144 `affected` + 1 `fix_deferred`): 94 do kernel (a resolver no
host) e 51 de espaço de usuário (12 CVEs, a acompanhar no Debian Security
Tracker). Mesmo após rebuild completo, a imagem continuará com esses
achados.

**R7 — Obsolescência e governança da imagem.** Construída em 14/04/2026,
a imagem acumulou 579 correções não aplicadas em cinco meses; a tag `latest`
resolve para o mesmo digest de `4.5.0`. [Interpretação] Sem processo de
rebuild periódico, o número de achados cresce continuamente
independentemente de mudanças no código do Orion.

**R8 — Ruído analítico do pacote de cabeçalhos.** 83,1% do relatório
refere-se a `linux-libc-dev`. [Interpretação] Esse volume distorce métricas
de risco, oculta os 122 achados relevantes e pode levar a decisões erradas
(por exemplo, bloquear o deploy por CVEs de drivers Wi-Fi que o container
não pode explorar).

**Cobertura do scanner (limitação).** [Interpretação] O Trivy não inventariou
as dependências compiladas no binário `contextBroker` (por exemplo,
libmicrohttpd, mongo-c-driver, RapidJSON), que constituem a superfície de
ataque principal do serviço na porta 1026. A ausência de achados nesses
componentes não significa ausência de vulnerabilidades.

### 5. Recomendações de correção

**RC1 — Reconstruir a imagem sobre a base Debian 13 atualizada (prioridade
imediata).** Executar `apt-get update && apt-get upgrade` no build ou usar
uma tag mais recente de `debian:13`. Versões-alvo indicadas pelo Trivy:

| Pacote-fonte | Instalada | Alvo |
|---|---|---|
| curl | 8.14.1-2+deb13u2 | 8.14.1-2+deb13u4 |
| gnutls28 | 3.8.9-3+deb13u2 | 3.8.9-3+deb13u4 |
| openssl | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| perl | 5.40.1-6 | 5.40.1-6+deb13u1 |
| libssh2 | 1.11.1-1 | 1.11.1-1+deb13u2 |
| util-linux | 2.41-5 | 2.41.5-0+deb13u1 |
| krb5 | 1.21.3-5 | 1.21.3-5+deb13u1 |
| pcre2 | 10.46-1~deb13u1 | 10.46-1~deb13u2 |
| sqlite3 | 3.46.1-7+deb13u1 | 3.46.1-7+deb13u2 |
| libcap2 | 1:2.75-10+b8 | 1:2.75-10+deb13u1 |
| gzip | 1.13-1 | 1.13-1+deb13u1 |
| nghttp2 | 1.64.0-1.1 | 1.64.0-1.1+deb13u1 |

Efeito esperado: elimina 71 das 122 ocorrências de espaço de usuário
(incluindo as 5 CRITICAL de GnuTLS e Perl) e 508 das 602 do kernel se
`linux-libc-dev` for atualizado em vez de removido.

**RC2 — Remover `linux-libc-dev` e demais artefatos de build.** O pacote de
cabeçalhos não é necessário em tempo de execução. Adotar build multi-stage:
compilar o Orion em um estágio com toolchain completo e copiar apenas o
binário e bibliotecas compartilhadas para um estágio final mínimo
(`debian:13-slim` ou distroless). Efeito: elimina as 602 ocorrências do
kernel (83,1% do relatório) e reduz a superfície de ataque. Verificar se
`CLEAN_DEV_TOOLS=1` no Dockerfile do projeto está sendo aplicado
corretamente (o pacote permaneceu na imagem).

**RC3 — Tratar as 4 vulnerabilidades sem correção do libcurl.** Enquanto o
Debian não publica correção para CVE-2026-8286, 8458, 8927 e 12064:
(a) restringir quem pode criar/alterar subscrições (autenticação e
autorização via PEP proxy, por exemplo Wilma/Keyrock no ecossistema FIWARE);
(b) aplicar política de saída de rede (NetworkPolicy/firewall) que limite os
destinos de notificação a hosts conhecidos; (c) não configurar proxy HTTP
com credenciais no container (mitiga CVE-2026-8927); (d) considerar compilar
o libcurl a partir do upstream corrigido ou acompanhar o Debian Security
Tracker para a publicação de 8.14.1-2+deb13u5 ou superior.

**RC4 — Manter o kernel do host atualizado.** Os 602 CVEs do kernel são
mitigados exclusivamente no host (versão ≥ 6.12.107 segundo as versões de
correção listadas). Em Kubernetes ou Docker, isso significa atualizar o
sistema operacional dos nós. Nenhuma alteração na imagem resolve esse
conjunto.

**RC5 — Endurecer a execução do container.** Manter `User=nobody`;
executar com `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
`--read-only` e perfil seccomp padrão; nunca `--privileged`. Isso neutraliza
na prática os vetores de escalada local (util-linux, libcap, libacl, systemd,
ncurses), inclusive os 7 CVEs sem correção desse grupo.

**RC6 — Verificar o uso de PCRE2 e SQLite pelo binário.** Executar `ldd
/usr/bin/contextBroker` na imagem para confirmar se `libpcre2-8` e
`libsqlite3` são carregados. Se não forem, removê-los da imagem final; se
forem, tratar CVE-2026-86145 como prioridade de correção (RC1 já cobre).

**RC7 — Acompanhar os 12 CVEs de espaço de usuário sem correção.** Registrar
em um arquivo `.trivyignore` com justificativa e data de revisão apenas os
que forem comprovadamente não aplicáveis (por exemplo, CVE-2026-16742 exige
systemd-homed, ausente; CVE-2026-12064 exige SFTP/SCP). Reavaliar a cada
scan.

**RC8 — Institucionalizar o scan.** Incluir o Trivy no pipeline de CI/CD com
gate em CRITICAL/HIGH corrigíveis (`--ignore-unfixed` para o gate,
relatório completo para registro), rebuild automático da imagem em
periodicidade fixa (por exemplo, semanal) ou a cada publicação de DSA
relevante, e fixar a imagem por digest em produção em vez da tag `latest`.

**RC9 — Complementar a cobertura do scanner.** Gerar SBOM da imagem
(`trivy image --format cyclonedx`) e inventariar manualmente as bibliotecas
compiladas no binário `contextBroker` (libmicrohttpd, mongo-c-driver,
RapidJSON, boost), que o Trivy não analisa. Correlacionar suas versões com
os avisos de segurança dos respectivos projetos.

**Ordem sugerida:** RC1 e RC2 (um único rebuild resolve ambos) → RC5 (sem
custo de código) → RC3 (mitigações para o que não tem patch) → RC4 (equipe de
infraestrutura) → RC6/RC7 (validação) → RC8/RC9 (processo).

---

## Rastreabilidade desta análise

- Imagem: `fiware/orion` (`fiware/orion:latest`, digest `sha256:dc29ec56…96edf`).
- Comando: `.\trivy.exe image --severity HIGH,CRITICAL -f json -o TRIVY_FIWARE_ORION_HIGH_CRITICAL.json fiware/orion`.
- Arquivo JSON: `D:\Documentos(D)\Estudos\FATEC\TCC\docx\Analise-2\TRIVY_FIWARE_ORION_HIGH_CRITICAL.json` (4.476.481 bytes).
- Trivy 0.71.2, banco `trivy-db:2` de 20/09/2026, execução em 2026-09-20T21:47:29-03:00.
- Contagens verificadas por script Python sobre o JSON: 724 ocorrências, 647 IDs distintos, 9 CRITICAL, 715 HIGH, 579 fixed, 144 affected, 1 fix_deferred.
