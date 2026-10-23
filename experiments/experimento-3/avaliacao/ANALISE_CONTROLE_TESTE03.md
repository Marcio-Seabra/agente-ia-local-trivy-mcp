# ANÁLISE DE CONTROLE — TESTE 03 (fiware/orion)

Documento de referência produzido **antes** da leitura dos três relatórios dos modelos (Granite 4.2, DeepSeek R1 e Qwen 3.5). Fonte única: o relatório JSON do Trivy gerado nesta rodada, após remoção das ocorrências com `Status = fixed`. Nenhuma fonte externa foi consultada.

---

## 0. Registro da coleta (Etapa 1 — dados brutos, sem interpretação)

| Item | Valor |
|---|---|
| Diretório de trabalho | `D:\Documentos(D)\Estudos\FATEC\TCC\docx\analise-3` |
| Comando | `trivy.exe image -f json -o TRIVY_FIWARE_ORION_TESTE03.json fiware/orion` |
| Binário utilizado | `D:\downloads(D)\trivy_0.74.0_windows-64bit\trivy.exe` |
| Versão do Trivy | 0.74.0 |
| Banco de vulnerabilidades | `trivy-db` versão 2, `UpdatedAt` 2026-10-19 19:08:34 UTC, baixado em 2026-10-19 21:22:57 UTC (atualizado automaticamente no início da execução) |
| Início da execução | 2026-10-19T18:22:33-03:00 |
| `CreatedAt` do relatório | 2026-10-19T18:23:04-03:00 |
| Imagem analisada | `fiware/orion` (`RepoTags`: `fiware/orion:latest`) |
| `RepoDigest` | `fiware/orion@sha256:dc29ec56888ac7d1a81bac6855fefe3cabcabcaec6bd46a3d9934bb875896edf` |
| `ImageID` | `sha256:8d8f5ae361f5a85fbab9250fa04e4c15e45f9e61f56a3f47207079d5f115cedc` |
| Data de criação da imagem (`ImageConfig.created`) | 2026-04-14T10:23:47Z |
| SO detectado | Debian 13.4 (`Metadata.OS`) |
| Pacotes de SO detectados pelo scanner (log) | 124 |
| Arquivos de dependência de linguagem | 0 |
| Quantidade de `Results` | 1 (`Target`: `fiware/orion (debian 13.4)`, `Class`: `os-pkgs`, `Type`: `debian`) |
| Total de ocorrências de vulnerabilidade | **6.663** |
| Distribuição por `Severity` | CRITICAL 12 · HIGH 820 · MEDIUM 4.439 · LOW 1.044 · UNKNOWN 348 |
| Distribuição por `Status` | fixed 5.522 · affected 1.138 · fix_deferred 2 · will_not_fix 1 |
| `VulnerabilityID` distintos | 6.280 |
| `PkgName` distintos | 70 |
| Arquivo salvo | `TRIVY_FIWARE_ORION_TESTE03.json` (31.005.127 bytes, JSON bruto, sem alterações) |

Metadados da imagem presentes no JSON (`Metadata.ImageConfig.config`): `Entrypoint = ["/usr/bin/contextBroker","-fg","-multiservice","-disableFileLog"]`, `User = nobody`, `ExposedPorts = {1026/tcp}`, `Env` inclui `GIT_REV_ORION=4.5.0` e `CLEAN_DEV_TOOLS=1`; `Healthcheck` executa `curl --fail -X GET http://localhost:1026/v2/entities?limit=1`.

---

## 1. Reprodução da preparação do Teste 03 (Etapa 2 — remoção de `Status = fixed`)

| Item | Valor |
|---|---|
| Ocorrências antes da remoção | 6.663 |
| Ocorrências removidas (`Status = fixed`) | **5.522** (5.344 IDs distintos; todas com `FixedVersion` preenchido) |
| Ocorrências restantes | **1.141** |
| `Severity` após a remoção | CRITICAL 3 · HIGH 115 · MEDIUM 604 · LOW 373 · UNKNOWN 46 |
| `Status` após a remoção | affected 1.138 · fix_deferred 2 · will_not_fix 1 |
| `VulnerabilityID` distintos restantes | 936 |
| `PkgName` distintos restantes | 60 |
| Pares (ID, pacote) distintos | 1.141 (não há duplicata exata) |
| Ocorrências restantes com `FixedVersion` | **0** |

Observação estrutural: a diferença entre 1.141 ocorrências e 936 IDs distintos decorre de um mesmo CVE ser atribuído a vários pacotes binários oriundos do mesmo pacote-fonte (por exemplo, os 6 CVEs do util-linux aparecem em 9 pacotes binários, gerando 54 ocorrências).

Ocorrências removidas, por pacote-fonte (apenas registro; estes dados **não** fizeram parte do material enviado aos modelos): linux-libc-dev 5.213 (FixedVersion entre 6.12.85-1 e 6.12.113-1); openssl/libssl3t64/openssl-provider-legacy 38 cada (3.5.6-1~deb13u2 a 3.5.7-1~deb13u3); curl/libcurl4t64 18 cada (8.14.1-2+deb13u3, u4, u7); perl-base 14 (5.40.1-6+deb13u1); libgnutls30t64 13 (3.8.9-3+deb13u4); libssh2-1t64 10; libpcre2-8-0 8; família util-linux 7 cada (2.41.3-1 e 2.41.5-0+deb13u1); família glibc 5 cada (2.41-12+deb13u3/u4); libsystemd0/libudev1 4 cada (257.13-1~deb13u1); liblzma5 3; gzip 2; família krb5 2 cada (1.21.3-5+deb13u1); libsqlite3-0 2; libcap2, libgcrypt20, libgcrypt20-dev, libnghttp2-14, libtasn1-6, sed 1 cada.

Nota sobre a condição original: no Teste 03 as 1.141 ocorrências foram divididas em partes enviadas separadamente aos modelos. O número de partes e o conteúdo de cada uma não constam do material disponível a esta análise de controle; o controle é, portanto, construído sobre o conjunto completo restante, com visão global que os modelos não possuíam em cada parte individual.

---

## 2. Distribuição das 1.141 ocorrências restantes por pacote

| Pacote-fonte (inferido pelo prefixo do `Title` e pela versão comum) | Pacotes binários (`PkgName`) | `InstalledVersion` | Ocorrências | IDs distintos | Severidades (por ID) |
|---|---|---|---:|---:|---|
| kernel (headers) | linux-libc-dev | 6.12.74-2 | 801 | 801 | CRITICAL 3 · HIGH 68 · MEDIUM 484 · LOW 201 · UNKNOWN 45 |
| curl | curl, libcurl4t64 | 8.14.1-2+deb13u2 | 78 | 39 | HIGH 2 · MEDIUM 10 · LOW 27 |
| glibc | libc-bin, libc-dev-bin, libc6, libc6-dev | 2.41-12+deb13u2 | 84 | 21 | MEDIUM 13 · LOW 8 |
| util-linux | bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount, util-linux | 2.41-5 (login: 1:4.16.0-2+really2.41-5) | 54 | 6 | HIGH 4 · MEDIUM 1 · LOW 1 |
| krb5 | krb5-locales, libgssapi-krb5-2, libk5crypto3, libkrb5-3, libkrb5support0 | 1.21.3-5 | 30 | 6 | MEDIUM 2 · LOW 4 |
| systemd | libsystemd0, libudev1 | 257.9-1~deb13u1 | 14 | 7 | HIGH 1 · MEDIUM 1 · LOW 5 |
| gnutls | libgnutls30t64 | 3.8.9-3+deb13u2 | 7 | 7 | LOW 7 |
| openldap | libldap-common, libldap2 | 2.6.10+dfsg-1 | 10 | 5 | LOW 5 |
| ncurses | libtinfo6, ncurses-base, ncurses-bin | 6.5+20250216-2 | 6 | 2 | HIGH 1 · LOW 1 |
| gcc/libstdc++ | gcc-14-base, libgcc-s1, libstdc++6 | 14.2.0-19 | 6 | 2 | MEDIUM 2 |
| tar | tar | 1.35+dfsg-3.1 | 5 | 5 | MEDIUM 3 · LOW 2 |
| perl | perl-base | 5.40.1-6 | 4 | 4 | HIGH 1 (fix_deferred) · MEDIUM 1 (fix_deferred) · LOW 1 · UNKNOWN 1 |
| coreutils | coreutils | 9.7-3 | 4 | 4 | LOW 4 |
| sqlite | libsqlite3-0 | 3.46.1-7+deb13u1 | 4 | 4 | MEDIUM 2 · LOW 2 |
| pam | libpam-modules, libpam-modules-bin, libpam-runtime, libpam0g | 1.7.0-5 | 4 | 1 | MEDIUM 1 |
| shadow | login.defs, passwd | 1:4.17.4-2 | 6 | 3 | LOW 3 |
| cyrus-sasl | libsasl2-2, libsasl2-modules, libsasl2-modules-db | 2.1.28+dfsg1-9 | 3 | 1 | MEDIUM 1 |
| libgcrypt | libgcrypt20, libgcrypt20-dev | 1.11.0-7 | 4 | 2 | LOW 2 |
| acl | libacl1 | 2.3.2-2+b1 | 2 | 2 | HIGH 1 · MEDIUM 1 |
| p11-kit | libp11-kit0 | 0.25.5-3 | 2 | 2 | MEDIUM 2 |
| zlib | zlib1g | 1:1.3.dfsg+really1.3.1-1+b1 | 2 | 2 | MEDIUM 2 |
| dash | dash | 0.5.12-12 | 2 | 2 | LOW 2 |
| apt | apt, libapt-pkg7.0 | 3.0.3 | 2 | 1 | LOW 1 |
| attr | libattr1 | 1:2.5.2-3 | 1 | 1 | MEDIUM 1 |
| bzip2 | libbz2-1.0 | 1.0.8-6 | 1 | 1 | MEDIUM 1 |
| nghttp2 | libnghttp2-14 | 1.64.0-1.1 | 1 | 1 | MEDIUM 1 |
| bash, bash-completion, diffutils, sysvinit-utils | (um pacote cada) | — | 4 | 4 | LOW 4 |

Fontes de dado (`DataSource`): 100% das 1.141 ocorrências vêm de `Debian Security Tracker`. `SeveritySource`: ausente em 758, `nvd` em 202, `debian` em 181. `CVSS` presente em 980 ocorrências (fornecedores: redhat 908, nvd 333, julia 48, bitnami 4) e ausente em 161.

---

## 3. Vulnerabilidades relevantes (ID e pacote)

Critério de seleção adotado pelo controle, a partir dos campos do relatório: (a) `Severity` CRITICAL ou HIGH; (b) `Severity` MEDIUM com `CVSS` V3 ≥ 7,0 de algum fornecedor ou com `Description` indicando elevação de privilégio/execução de código; (c) `Status` diferente de `affected` (fix_deferred / will_not_fix), por indicar decisão explícita do mantenedor. Todas as demais ocorrências são registradas em bloco. Nenhuma das 1.141 ocorrências possui `FixedVersion`.

### 3.1 CRITICAL (3 IDs, todos em `linux-libc-dev 6.12.74-2`, `Status = affected`)

| ID | Pacote | Título (campo `Title`) | Observação a partir dos dados |
|---|---|---|---|
| CVE-2026-43185 | linux-libc-dev | kernel: ksmbd: fix signededness bug in smb_direct_prepare_negotiation() | `VendorSeverity` apenas `ubuntu: 4`; sem `CVSS`; `CweIDs` CWE-674. Descrição: valor assinado/não assinado em SMB Direct permite heap buffer overflow via mensagem maliciosa. |
| CVE-2026-63825 | linux-libc-dev | kernel: gcov: use atomic counter updates to fix concurrent access crashes | `VendorSeverity` apenas `ubuntu: 4`; sem `CVSS`; sem CWE. Descrição: contadores GCOV globais em `inflate_fast()` causam escrita fora dos limites durante IPComp. |
| CVE-2026-93221 | linux-libc-dev | (título truncado: "In the Linux kernel, the following vulnerability has been resolved: n…") | `VendorSeverity` apenas `ubuntu: 4`; sem `CVSS`. Descrição: `nfsd` — flags booleanas de `nfsd_net` acessadas concorrentemente sem serialização. |

Observação: a severidade CRITICAL dos três itens provém exclusivamente de `VendorSeverity.ubuntu = 4`; nenhum tem `SeveritySource`, `CVSS` ou severidade NVD/Red Hat no registro.

### 3.2 HIGH fora do kernel (10 IDs distintos, 47 ocorrências)

| ID | Pacote(s) | Instalada | Status | CVSS (campo `CVSS`) | Título |
|---|---|---|---|---|---|
| CVE-2026-76642 | util-linux (+bsdutils, libblkid1, liblastlog2-2, libmount1, libsmartcols1, libuuid1, login, mount) | 2.41-5 | affected | redhat 7.8 | failed external mount helper still runs privileged X-mount post-hooks |
| CVE-2026-78408 | idem (9 pacotes) | 2.41-5 | affected | redhat 7.9 | nsenter --join-cgroup leaks root cgroup migration authority |
| CVE-2026-78409 | idem (9 pacotes) | 2.41-5 | affected | redhat 7.0 | X-mount.subdir detached-tree resolution can escape via intermediate symlinks |
| CVE-2026-78410 | idem (9 pacotes) | 2.41-5 | affected | redhat 7.8 | restricted bind mounts do not pin the source, allowing X-mount.owner/group/mode redirection |
| CVE-2026-12064 | curl, libcurl4t64 | 8.14.1-2+deb13u2 | affected | redhat 7.5 · julia 7.5 | SSH host verification bypass when using schemeless URLs with SFTP/SCP |
| CVE-2026-8458 | curl, libcurl4t64 | 8.14.1-2+deb13u2 | affected | redhat 8.1 · julia 6.5 | Unauthorized connection reuse due to a logical error (Negotiate) |
| CVE-2026-54369 | libacl1 | 2.3.2-2+b1 | affected | redhat 7.1 | acl: Symlink traversal privilege escalation via libacl functions |
| CVE-2026-16742 | libsystemd0, libudev1 | 257.9-1~deb13u1 | affected | redhat 8.8 | systemd-homed: Local privilege escalation via missing home-record signature verification |
| CVE-2025-69720 | libtinfo6, ncurses-base, ncurses-bin | 6.5+20250216-2 | affected | nvd 7.8 · redhat 7.8 · julia 7.8 | ncurses: Buffer overflow (stack) em `infocmp` |
| CVE-2026-9538 | perl-base | 5.40.1-6 | **fix_deferred** | nvd 7.5 · redhat 7.5 | perl-Archive-Tar: Denial of Service via crafted tar header |

### 3.3 HIGH no kernel (68 IDs em `linux-libc-dev 6.12.74-2`)

Todos `Status = affected`, sem `FixedVersion`. Maior `CVSS` entre eles: CVE-2026-74752 (8.8, "sctp: validate cookie AUTH state before use") e CVE-2026-89631 (8.1, "smb: client: reject a tree connect response whose byte count is too small"); vários em 7.8 (por exemplo CVE-2019-19449, CVE-2019-19814, CVE-2021-3847, CVE-2024-21803, CVE-2025-38137, CVE-2025-38187, CVE-2025-68735). Subsistemas recorrentes nos títulos: f2fs, drm/amd*, KVM, RDMA, wifi/mac80211, ksmbd/smb, bpf, netfilter, xfrm, nfsd, dm-verity. Faixa de anos dos IDs: 2013 a 2026; 15 IDs anteriores a 2025 (por exemplo CVE-2013-7445, CVE-2021-3864).

### 3.4 MEDIUM com indicadores de maior gravidade nos dados (seleção)

| ID | Pacote(s) | CVSS | Por que entra na seleção |
|---|---|---|---|
| CVE-2026-86805 | glibc (libc6 e 3 outros) | redhat 7.0 | `Title`: "Privilege escalation and arbitrary code execution via TOCTOU race condition in dynamic loader" (ld.so, programas setuid, requer `fs.protected_hardlinks` desabilitado) |
| CVE-2026-95818 | glibc | redhat 7.0 | Stack overflow em ld.so para programas AT_SECURE (DoS + divulgação limitada) |
| CVE-2026-19499 | glibc | redhat 6.8 | Buffer overflow em `strfmon` (requer caminho de código específico) |
| CVE-2026-95619 | gcc-14-base, libgcc-s1, libstdc++6 | redhat 7.7 | Integer overflow em `operator new` alinhado (alocação subdimensionada) |
| CVE-2026-102010 | gcc-14-base, libgcc-s1, libstdc++6 | redhat 7.0 | Use-after-free em `erase_if` de binary heap (libstdc++) |
| CVE-2026-107161 | libsasl2-2, libsasl2-modules, libsasl2-modules-db | redhat 7.5 | Heap overflow em DIGEST-MD5 (`add_to_challenge`), servidor malicioso compromete cliente |
| CVE-2026-8932 | curl, libcurl4t64 | redhat 7.5 | Bypass de verificação de reuso de conexão mTLS |
| CVE-2026-9079 | curl, libcurl4t64 | redhat 7.5 · julia 9.8 | Credenciais de proxy não limpas |
| CVE-2026-9545 | curl, libcurl4t64 | redhat 7.5 | Vazamento via sessão SSL em cache + early data (HTTP/3) |
| CVE-2026-9080 | curl, libcurl4t64 | redhat 7.3 | Use-after-free via `curl_easy_pause()` em callback |
| CVE-2026-10536 / CVE-2026-11856 / CVE-2026-8926 | curl, libcurl4t64 | redhat 4.7/6.5/4.8 · julia 9.8/9.8/9.1 | Divergência forte entre fornecedores de CVSS; Debian classifica MEDIUM |
| CVE-2026-54370 | libacl1 | redhat 6.3 | TOCTOU symlink em getfacl/setfacl (elevação local) |
| CVE-2026-54371 | libattr1 | redhat 6.3 | Symlink traversal em getfattr/setfattr (elevação local) |
| CVE-2026-15059 | libsystemd0, libudev1 | redhat 5.5 | systemd-oomd: usuário local termina processos arbitrários |
| CVE-2026-15534 | perl-base | redhat 5.7 | **fix_deferred**; `Title`: "Arbitrary code execution via out-of-bounds memory access in regular expression engine" |
| CVE-2026-3184 | util-linux (9 pacotes) | nvd 5.3 · redhat 3.7 | Bypass de controle de acesso PAM via `login -h` |
| CVE-2026-5704 / CVE-2026-18477 / CVE-2026-18508 | tar | 5.0–5.5 / 4.4 / 4.4 | Injeção de arquivo oculto; TOCTOU em restauração; escape de `--one-top-level` |
| CVE-2026-27171 / CVE-2026-85091 | zlib1g | nvd 5.5 / sem CVSS | Loop infinito em `crc32_combine64`; heap overflow em `gz_vacate()` após stall de escrita |
| CVE-2026-107708 / CVE-2026-107778 | krb5 (5 pacotes) | redhat 4.9 / 6.5 | NULL deref no KDC (S4U2Proxy) e em `make_cred_list()` (GSS acceptor) |
| CVE-2026-13757 / CVE-2026-18938 | libp11-kit0 | redhat 6.2 / 6.2 | Exaustão de pilha e integer overflow (32 bits) no parser RPC |
| CVE-2026-54411 | pam (4 pacotes) | redhat 4.8 | Timing attack em `pam_userdb` |
| CVE-2026-50812 / CVE-2026-50813 | libsqlite3-0 | redhat 5.5 / 5.5 | Session Extension: NULL deref e divulgação |
| CVE-2026-42250 | libbz2-1.0 | redhat 5.0 | Off-by-one em `bzip2recover` |
| CVE-2026-58055 | libnghttp2-14 | redhat 5.4 | Request smuggling no proxy `nghttpx` |
| CVE-2026-80229 | curl, libcurl4t64 | sem CVSS | Heap use-after-free com OpenSSL 3 providers no multi interface |

### 3.5 Ocorrências com `Status` diferente de `affected`

| ID | Pacote | Status | Severity |
|---|---|---|---|
| CVE-2026-9538 | perl-base | fix_deferred | HIGH |
| CVE-2026-15534 | perl-base | fix_deferred | MEDIUM |
| CVE-2025-71188 | linux-libc-dev | will_not_fix | MEDIUM ("dmaengine: lpc18xx-dmamux: fix device leak") |

### 3.6 Blocos restantes (registrados, não destacados individualmente)

- **LOW (373 ocorrências, ~320 IDs distintos)**: 201 no kernel; 27 IDs em curl (vários com CVSS redhat entre 5,9 e 8,1, por exemplo CVE-2025-15079 "Host verification bypass during SSH transfers" redhat 8.1, CVE-2026-9547 "MITM via SSH host key bypass" 7.4, CVE-2026-86414 "leaking host credentials to HTTP proxy" 6.5); 8 em glibc (IDs de 2010–2019, inclusive CVE-2019-1010022 com nvd 9.8 e CVE-2019-1010023 nvd 8.8, ambos classificados LOW pela fonte Debian); 7 em gnutls (5 publicados em 2026-10-08, dois com redhat 7.4: CVE-2026-88647 hostname verification bypass e CVE-2026-88648 cross-domain certificate restriction bypass); 5 em openldap; 5 em systemd; 4 em krb5; 4 em coreutils; 3 em shadow; e itens isolados em apt, bash (TEMP-0841856-B18BAF), bash-completion, dash, diffutils, libgcrypt, ncurses, perl, sqlite, sysvinit-utils (TEMP-0517018-A83CE6) e tar (CVE-2005-2541 nvd 10.0, TEMP-0290435-0B57B5). Quatro IDs têm formato `TEMP-…` (identificadores temporários do Debian Security Tracker, sem CVE).
- **UNKNOWN (46)**: 45 no kernel e CVE-2026-82560 em perl-base (Pod::Text, exaustão de CPU/memória), todos sem `VendorSeverity` relevante ou sem `CVSS`.
- **MEDIUM restantes do kernel (484)**: predominância de CWE-476 (NULL deref), CWE-401 (memory leak), CWE-416 (UAF), CWE-362 (race), CWE-125 (OOB read); CVSS máximo 7,8 nos poucos que possuem pontuação.

---

## 4. Impacto provável

Convenção: **[dado]** = afirmação lida diretamente dos campos do relatório; **[inferência]** = conclusão derivada dos dados, sem confirmação no relatório.

### 4.1 Kernel (`linux-libc-dev`, 801 ocorrências)

- [dado] As 801 ocorrências estão atribuídas ao pacote `linux-libc-dev 6.12.74-2` (`PURL` com `arch=all`), e as descrições tratam de correções no código do kernel Linux (ksmbd, nfsd, bpf, drm, wifi, KVM, RDMA etc.).
- [dado] Nenhuma possui `FixedVersion`; 800 têm `Status = affected`, 1 `will_not_fix`.
- [inferência] O pacote tem sufixo `-dev` e arquitetura `all`, características de pacote de desenvolvimento; o relatório não contém informação sobre o kernel efetivamente em execução no host. A exposição real do container a estas falhas **não pode ser determinada a partir do relatório**. O que os dados sustentam é que o pacote vulnerável está presente na imagem e concentra 70% das ocorrências restantes e 100% das CRITICAL.
- [inferência] Os três CRITICAL (ksmbd/SMB Direct, gcov/IPComp, nfsd) dependem de subsistemas de servidor de arquivos de rede e de instrumentação de compilador; nada no relatório indica que a imagem utilize tais subsistemas.

### 4.2 util-linux (4 HIGH + 1 MEDIUM + 1 LOW, em 9 pacotes binários)

- [dado] As quatro HIGH descrevem elevação de privilégio **local** por usuário não privilegiado explorando `mount` SUID com opções `X-mount.*`, entradas de `fstab` autorizadas, ou `nsenter --join-cgroup` executado por operador privilegiado. CVSS redhat 7,0–7,9.
- [dado] CVE-2026-3184 (MEDIUM) trata de `login -h` e canonicalização de hostname para `PAM_RHOST`.
- [dado] CVE-2022-0563 (LOW) requer compilação com libreadline (chfn/chsh).
- [inferência] A imagem executa com `User = nobody` e `Entrypoint = contextBroker` [dado]; os cenários descritos exigem um atacante local com shell no container e configuração de `fstab`/mount helpers, ou uso de `nsenter`/`login`, nenhum dos quais consta do relatório. Impacto condicionado a esses pré-requisitos.

### 4.3 curl / libcurl4t64 (2 HIGH + 10 MEDIUM + 27 LOW)

- [dado] As descrições concentram-se em: verificação de host SSH (SFTP/SCP), reuso indevido de conexões autenticadas (Negotiate, mTLS), vazamento de credenciais (`.netrc`, proxy, Digest, SigV4, cookies), use-after-free em cenários específicos (HTTP/2 stream dependency + `curl_easy_reset`, `curl_easy_pause` em callback, OpenSSL providers, server push), HSTS, FTP wildcard, TFTP, IMAP, WebSockets.
- [dado] A imagem usa `curl --fail -X GET http://localhost:1026/...` no `Healthcheck`.
- [inferência] O uso documentado no relatório é HTTP simples para localhost, sem SSH, proxy, autenticação ou TLS; a maioria dos cenários descritos não se aplica a esse uso. O impacto relevante seria para qualquer outro consumidor de `libcurl4t64` na imagem, o que o relatório não permite determinar.
- [dado] Há divergência marcante entre fornecedores de CVSS em vários IDs (julia 9,8 vs. redhat 4,7 em CVE-2026-10536; julia 9,8 vs. redhat 6,5 em CVE-2026-11856; julia 9,1 vs. redhat 4,8 em CVE-2026-8926). A severidade Debian adotada pelo Trivy é MEDIUM.

### 4.4 glibc (13 MEDIUM + 8 LOW, em 4 pacotes)

- [dado] Dois itens com CVSS 7,0 envolvem o loader dinâmico em programas setuid/AT_SECURE (CVE-2026-86805 TOCTOU com `$ORIGIN` em DT_RPATH, exigindo `fs.protected_hardlinks` desabilitado; CVE-2026-95818 stack overflow). Os demais MEDIUM são DoS/overflows em funções específicas (`strfmon`, `tdelete`, `wordexp`, `iconv` JISX0213, resolver stub, `nscd`, funções `ns_printrr*` depreciadas, `fopen` com `,ccs=`).
- [dado] Várias descrições afirmam explicitamente baixa aplicabilidade ("not seen in applications in common GNU/Linux distributions", "no network-facing application impact is known", "for application debugging only").
- [dado] Os 8 LOW são IDs de 2010–2019 com CVSS NVD alto (até 9,8), classificados LOW pela fonte Debian.
- [inferência] Impacto geral baixo a moderado e dependente de caminhos de código específicos; a glibc é biblioteca base de todos os binários da imagem, portanto a superfície potencial é ampla, mas o relatório não evidencia uso dos caminhos vulneráveis.

### 4.5 systemd (libsystemd0, libudev1)

- [dado] CVE-2026-16742 (HIGH, redhat 8,8) refere-se a `systemd-homed`; CVE-2026-15059 (MEDIUM) a `systemd-oomd`; os LOW tratam de journald, sealing de logs (2023) e TOCTOU (2013).
- [inferência] Os pacotes presentes são apenas as bibliotecas `libsystemd0` e `libudev1`; o relatório não mostra os daemons `systemd-homed`/`systemd-oomd` na imagem. A atribuição decorre do pacote-fonte compartilhado; o impacto efetivo na imagem não é sustentado pelos dados.

### 4.6 ncurses (libtinfo6, ncurses-base, ncurses-bin)

- [dado] CVE-2025-69720 (HIGH, CVSS 7,8) é stack overflow em `infocmp` (`progs/infocmp.c`), ferramenta de linha de comando. CVE-2025-6141 (LOW) idem, stack overflow.
- [inferência] Requer execução de `infocmp` sobre entrada maliciosa; não há indicação no relatório de uso dessa ferramenta pelo serviço.

### 4.7 acl / attr

- [dado] CVE-2026-54369 (HIGH 7,1) e CVE-2026-54370 (MEDIUM) em `libacl1`; CVE-2026-54371 (MEDIUM) em `libattr1`: symlink traversal / TOCTOU com elevação de privilégio **quando um processo privilegiado** opera sobre caminhos controlados pelo atacante.
- [inferência] Container com `User = nobody` reduz o cenário de "processo privilegiado"; impacto condicionado.

### 4.8 perl-base

- [dado] CVE-2026-9538 (HIGH 7,5, `fix_deferred`): DoS por exaustão de memória em `Archive::Tar`; CVE-2026-15534 (MEDIUM, `fix_deferred`): leitura/escrita fora dos limites no motor de regex com entrada ≥ 286 MB; CVE-2026-82560 (UNKNOWN): exaustão em `Pod::Text`; CVE-2011-4116 (LOW): `File::Temp`.
- [inferência] `fix_deferred` indica decisão do mantenedor de adiar correção; o impacto depende de scripts Perl processarem entrada não confiável, o que o relatório não evidencia.

### 4.9 libstdc++ / gcc

- [dado] Dois MEDIUM com CVSS 7,0 e 7,7: UAF em `erase_if` de `priority_queue` e integer overflow em `operator new` alinhado com tamanhos grandes.
- [inferência] `libstdc++6` é biblioteca de tempo de execução presente na imagem; aplicável a programas C++ que exercitem exatamente esses caminhos. O relatório não informa se `contextBroker` o faz.

### 4.10 Demais bibliotecas (krb5, sasl, nghttp2, p11-kit, pam, sqlite, tar, zlib, bzip2, gnutls, openldap, libgcrypt, coreutils, shadow, dash, apt, bash, diffutils, sysvinit)

- [dado] Predominam DoS (NULL deref, loop infinito, exaustão), vazamentos de informação e falhas que exigem servidor malicioso (sasl DIGEST-MD5, krb5 KDC cross-realm), arquivo malicioso (tar, bzip2recover, zlib gzprintf) ou acesso local (p11-kit RPC socket, pam_userdb timing).
- [dado] Em gnutls, 5 dos 7 LOW foram publicados em 2026-10-08, alguns com CVSS redhat 7,4 (bypass de verificação de hostname e de restrição de domínio); a fonte Debian classifica LOW.
- [inferência] Impacto individual baixo no contexto de um serviço HTTP na porta 1026 executando como `nobody`, salvo onde a aplicação consuma dados externos por essas bibliotecas (por exemplo, TLS via gnutls ou LDAP/SASL), o que o relatório não permite verificar.

### 4.11 Visão agregada

- [dado] 0 de 1.141 ocorrências possuem correção disponível na distribuição no momento da coleta (`FixedVersion` ausente; `Status` affected/fix_deferred/will_not_fix).
- [dado] 70% das ocorrências e 100% das CRITICAL concentram-se em um único pacote de desenvolvimento (`linux-libc-dev`).
- [dado] Dos 78 IDs HIGH distintos, 68 estão no kernel e 10 em pacotes de espaço de usuário; destes 10, 4 são da mesma família (util-linux) e descrevem elevação local via `mount`/`nsenter`.
- [inferência] O perfil de risco residual da imagem, com base apenas nos dados, é dominado por (i) presença de pacotes de desenvolvimento desnecessários a um runtime e (ii) falhas de elevação de privilégio local que pressupõem um atacante já com execução no container.

---

## 5. Recomendações de correção práticas

Todas as recomendações abaixo derivam dos campos do relatório. Como **nenhuma** das 1.141 ocorrências tem `FixedVersion`, não é possível, a partir dos dados restantes, indicar versão-alvo que corrija qualquer delas; recomendações de "atualizar para a versão X" não são sustentáveis para este conjunto.

1. **Remover pacotes de desenvolvimento da imagem final** — `linux-libc-dev`, `libc6-dev`, `libc-dev-bin`, `libgcrypt20-dev` [dado: todos listados como `PkgName` vulneráveis]. A variável `CLEAN_DEV_TOOLS=1` no `Env` e o `RUN` único com `apt-get` no histórico [dado] indicam intenção de limpeza que não alcançou esses pacotes. Efeito mensurável nos dados: eliminação de 801 ocorrências do kernel (incluindo as 3 CRITICAL e 68 HIGH) e de 21 + 21 + 2 ocorrências em libc6-dev, libc-dev-bin e libgcrypt20-dev, reduzindo o conjunto restante de 1.141 para 296 ocorrências. [inferência: requer verificar que `contextBroker` não depende desses pacotes em tempo de execução.]

2. **Manter execução não privilegiada e restringir capacidades de mount/namespace** — a imagem já define `User = nobody` [dado]. As 4 HIGH do util-linux descrevem cenários com `mount` SUID, `fstab` e `nsenter --join-cgroup` [dado]; recomenda-se não conceder `CAP_SYS_ADMIN`, montar o sistema de arquivos raiz como somente leitura e não incluir `fstab` com entradas `user`/`X-mount.*` [inferência derivada das descrições]. Alternativa: remover o bit SUID de `/usr/bin/mount` e `/usr/bin/umount` se não forem necessários [inferência].

3. **Avaliar a necessidade de `curl` no runtime** — o único uso evidenciado é o `Healthcheck` HTTP para localhost [dado]. Se mantido, restringir a esse uso; não utilizar SFTP/SCP, proxies autenticados, `.netrc`, Negotiate/Digest ou HTTP/3 com early data, que são os cenários das falhas descritas [dado]. Para outras aplicações que usem `libcurl4t64`, revisar se exercitam `CURLOPT_STREAM_DEPENDS`, `curl_easy_pause` em callbacks, FTP wildcard ou reuso de handles entre origens [dado].

4. **Tratar `fix_deferred` e `will_not_fix` como risco aceito a documentar** — CVE-2026-9538 e CVE-2026-15534 (perl-base) e CVE-2025-71188 (linux-libc-dev) [dado]. Para o Perl, evitar processar arquivos tar ou regex sobre entrada não confiável com scripts Perl na imagem [inferência]; verificar se `perl-base` é necessário ao runtime.

5. **Reconstruir a imagem a partir de base atualizada e re-escanear** — a imagem foi criada em 2026-04-14 [dado]. O relatório completo mostra 5.522 ocorrências já corrigidas na distribuição (removidas nesta preparação), com `FixedVersion` conhecida para openssl (3.5.7-1~deb13u3), curl (8.14.1-2+deb13u7), perl-base (5.40.1-6+deb13u1), gnutls (3.8.9-3+deb13u4), util-linux (2.41.5-0+deb13u1), glibc (2.41-12+deb13u4), systemd (257.13-1~deb13u1), krb5 (1.21.3-5+deb13u1), linux-libc-dev (até 6.12.113-1) e outros [dado do relatório completo; **não disponível aos modelos**]. Um `apt-get upgrade` em rebuild não corrige nenhuma das 1.141 restantes, mas elimina as 5.522 corrigidas.

6. **Acompanhar os IDs HIGH sem correção em pacotes de runtime** — CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410 (util-linux), CVE-2026-12064 e CVE-2026-8458 (curl), CVE-2026-54369 (libacl1), CVE-2026-16742 (systemd), CVE-2025-69720 (ncurses) [dado]: re-executar o scanner periodicamente para detectar o surgimento de `FixedVersion`.

7. **Mitigações de endurecimento sustentadas pelas descrições**: manter `fs.protected_hardlinks` habilitado no host (CVE-2026-86805 só é explorável com ele desabilitado [dado]); não expor sockets RPC do p11-kit nem `systemd-oomd`/`systemd-homed` no container (os daemons não constam da imagem [dado]); não executar `infocmp`, `bzip2recover`, `getfacl/setfacl`, `getfattr/setfattr` como processo privilegiado sobre caminhos controláveis [dado das descrições].

8. **Reduzir a imagem ao mínimo necessário ao `contextBroker`** — remoção de pacotes sem função evidente no runtime (tar, bzip2, diffutils, bash-completion, perl-base, krb5, ldap, sasl, p11-kit) eliminaria as respectivas ocorrências [inferência sobre necessidade; contagem por pacote é dado].

9. **Tratar a severidade com cautela diante das divergências de fornecedor** — os três CRITICAL têm severidade exclusivamente `ubuntu`, sem CVSS; vários MEDIUM/LOW têm CVSS NVD ou julia muito superior à classificação Debian adotada [dado]. A priorização deve considerar o campo `VendorSeverity` e não apenas `Severity`.

---

## 6. Limitações desta análise de controle

- Construída sobre o conjunto completo de 1.141 ocorrências; os modelos receberam partes independentes e não tinham visão global.
- O relatório não lista pacotes instalados sem vulnerabilidade, nem informa dependências do `contextBroker`; afirmações sobre necessidade de pacotes são inferências.
- O relatório não contém informação sobre o kernel do host, o runtime de containers ou a configuração de execução; a aplicabilidade das falhas de kernel e de util-linux não pode ser determinada pelos dados.
- Os dados do Trivy desta coleta (banco de 2026-10-19) podem diferir dos dados vistos pelos modelos na execução original; comparações pontuais entre PDFs e este JSON serão marcadas como inconclusivas quando a presença do dado na execução original não puder ser estabelecida.
- Nenhuma fonte externa (NVD, CVE.org, Debian Security Tracker on-line, GitHub, documentação de fornecedores) foi consultada.
