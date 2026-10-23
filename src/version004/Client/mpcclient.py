import asyncio
import time
import sys
import psutil
import matplotlib.pyplot as plt

# Compatibilidade: o GPUtil depende do módulo distutils, removido de versões recentes do Python.
import shutil
import types
if 'distutils' not in sys.modules:
    sys.modules['distutils'] = types.ModuleType('distutils')
    sys.modules['distutils'].spawn = types.ModuleType('distutils.spawn')
    sys.modules['distutils'].spawn.find_executable = shutil.which

import GPUtil

from mcp import ClientSession
from mcp.client.stdio import (
    stdio_client,
    StdioServerParameters
)

# =========================================================
# IMPORTAÇÃO PARA USO EM REDE (Descomentar para usar)
# Importa o cliente SSE (Server-Sent Events) necessário 
# para a comunicação web (HTTP) com o servidor MCP.
# =========================================================
# from mcp.client.sse import sse_client

async def main():
    print("\n====================================")
    print("       TRIVY MCP CLIENT")
    print("====================================")

    print("\nSelecione o tipo de análise:\n")
    print("[ 1 ] Docker Image")
    print("[ 2 ] Filesystem")
    print("[ 3 ] Code Repository")

    opcao = input("\nDigite o número da opção: ")
    match opcao:
        case "1":
            print("\nOpção selecionada: Docker Image")
            alvo = input("Digite o nome da imagem docker: ")
            tipo_alvo = "Docker Image"
        case "2":
            print("\nOpção selecionada: Filesystem")
            alvo = input("Digite o PATH do projeto: ")
            tipo_alvo = "Filesystem"
        case "3":
            print("\nOpção selecionada: Code Repository")
            alvo = input("Digite a URL do repositório para analise: ")
            tipo_alvo = "Code Repository"
        case _:
            print("\nOpção inválida.")
            return

    print("\n====================================")
    print("       TIPO DE SCANNER")
    print("====================================")
    print("\n[ 1 ] Vulnerabilidades")
    print("[ 2 ] Configurações incorretas")
    print("[ 3 ] Segredos")
    print("[ 4 ] Licenças")

    scanner = input("\nDigite o número da opção: ")
    match scanner:
        case "1":
            tipo_scanner = "Vulnerabilidades"
        case "2":
            tipo_scanner = "Configurações incorretas"
        case "3":
            tipo_scanner = "Segredos"
        case "4":
            tipo_scanner = "Licenças"
        case _:
            print("\nOpção inválida.")
            return

    print("\n====================================")
    print("       ANÁLISE SELECIONADA")
    print("====================================")
    print(f"Tipo: {tipo_alvo}")
    print(f"Alvo: {alvo}")
    print(f"Scanner: {tipo_scanner}")

    mensagem = f"""
Realizar análise de segurança utilizando o Trivy.

Tipo de alvo: {tipo_alvo}
Alvo: {alvo}
Scanner solicitado: {tipo_scanner}
"""

    print("\n====================================")
    print("       MENSAGEM PARA O MCP")
    print("====================================")
    print(mensagem)


    # =========================================================
    # CONEXÃO EM REDE VIA HTTP/SSE (Alternativa)
    # Descomente o bloco abaixo e comente o bloco STDIO a seguir
    # caso queira conectar a um servidor rodando na rede local.
    # =========================================================
    #
    # Define a URL do servidor. Substitua "127.0.0.1" pelo IP 
    # da máquina onde o servidor está rodando na rede local.
    # url_servidor = "http://127.0.0.1:8000/sse"
    #
    # Inicia a conexão de rede com o servidor usando o sse_client
    # async with sse_client(url=url_servidor) as (read, write):
    #     async with ClientSession(read, write) as session:
    #         await session.initialize()
    #         # O restante do código de execução das ferramentas (if opcao == "1"...)
    #         # deve ser recuado para dentro deste bloco 'with'.
    #
    # =========================================================


    # =========================================================
    # CONEXÃO LOCAL VIA STDIO (Atual)
    # Comente este bloco inteiro se for utilizar a rede acima
    # =========================================================
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[r"D:\Projeto\testes-gpt\server\mcpservergpt008.py"]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
    # =========================================================

            tools = await session.list_tools()

            print("\n====================================")
            print("       SERVIDOR MCP")
            print("====================================")
            print("Servidor MCP conectado.")

            if opcao == "1":
                tarefa = asyncio.create_task(
                    session.call_tool(
                        "analyze_container",
                        {"image": alvo}
                    )
                )

                print("\nAguardando resposta do servidor e monitorando recursos...")
                
                # Variáveis para o gráfico
                historico_tempo = []
                historico_cpu = []
                historico_ram = []
                historico_gpu = []
                historico_vram = []

                psutil.cpu_percent() # Inicializa o contador do psutil
                inicio = time.time()

                while not tarefa.done():
                    tempo = int(time.time() - inicio)
                    
                    # Coleta de métricas
                    cpu_atual = psutil.cpu_percent()
                    ram_atual = psutil.virtual_memory().percent
                    
                    gpus = GPUtil.getGPUs()
                    gpu_atual = gpus[0].load * 100 if gpus else 0.0
                    vram_atual = gpus[0].memoryUtil * 100 if gpus else 0.0

                    historico_tempo.append(tempo)
                    historico_cpu.append(cpu_atual)
                    historico_ram.append(ram_atual)
                    historico_gpu.append(gpu_atual)
                    historico_vram.append(vram_atual)

                    print(
                        f"\rTempo: {tempo:02d}s | CPU: {cpu_atual}% | RAM: {ram_atual}% | GPU: {gpu_atual:.1f}% | VRAM: {vram_atual:.1f}%",
                        end="",
                        flush=True
                    )

                    await asyncio.sleep(1)

                result = await tarefa
                tempo_total = int(time.time() - inicio)

                print(f"\n\rTempo de espera total: {tempo_total:02d} segundos")

                print("\n====================================")
                print("       RESPOSTA DO SERVIDOR")
                print("====================================")
                texto = result.content[0].text
                print(texto)

                # Geração do Gráfico após a resposta
                plt.figure(figsize=(10, 6))
                plt.plot(historico_tempo, historico_cpu, label='CPU (%)', color='blue')
                plt.plot(historico_tempo, historico_ram, label='RAM (%)', color='green')
                
                if gpus:
                    plt.plot(historico_tempo, historico_gpu, label='GPU (%)', color='red')
                    plt.plot(historico_tempo, historico_vram, label='VRAM (%)', color='purple')
                
                plt.title('Monitoramento de Recursos Durante a Análise')
                plt.xlabel('Tempo (segundos)')
                plt.ylabel('Uso (%)')
                plt.ylim(0, 100)
                plt.legend()
                plt.grid(True, linestyle='--', alpha=0.7)
                
                print("\nGerando gráfico de consumo de recursos...")
                plt.show()

            else:
                print("\nA opção selecionada ainda não possui")
                print("uma ferramenta correspondente no servidor MCP.")
                print("A mensagem foi montada e está pronta para")
                print("ser integrada ao servidor posteriormente.")

if __name__ == "__main__":
    asyncio.run(main())