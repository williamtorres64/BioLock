# BioLock

Sistema web de controle de acesso com autenticacao por senha e reconhecimento facial. O projeto foi desenvolvido como uma aplicacao academica em Python, com FastAPI, SQLite, SQLAlchemy, OpenCV e `face_recognition`.

## Requisitos

- Python 3.10 ou superior
- Webcam acessivel pelo navegador
- Linux, macOS ou Windows
- Navegador com suporte a `getUserMedia`

A instalacao de `face-recognition` pode exigir ferramentas de compilacao e as dependencias nativas do `dlib`, especialmente em Linux.

## Instalacao

Clone o repositorio e entre na pasta do projeto:

```bash
git clone <URL_DO_REPOSITORIO>
cd BioLock
```

Crie e ative um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

No Windows PowerShell, use:

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
```

Instale as dependencias:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Criando o primeiro administrador

Use uma imagem local com exatamente um rosto reconhecivel:

```bash
python bootstrap_admin.py admin "Nome do Administrador" caminho/para/foto.jpg
```

A senha sera solicitada no terminal e nao sera exibida. O comando cria o banco `vault_security.db` e cadastra o administrador com nivel de acesso 100.

A imagem usada no cadastro nao e copiada para o banco, mas o vetor numerico do rosto e armazenado como dado biometrico sensivel. Nao compartilhe o banco ou imagens de cadastro.

## Executando a aplicacao

```bash
python main.py
```

Depois, abra [http://127.0.0.1:8000](http://127.0.0.1:8000) no navegador e permita o acesso a webcam.

Tambem e possivel iniciar diretamente com Uvicorn:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

O modo `--reload` e apropriado apenas para desenvolvimento.

## Fluxo da aplicacao

- A pagina inicial direciona para o cadastro do primeiro administrador quando ainda nao existe um administrador.
- Novos usuarios podem solicitar cadastro com senha e referencia facial.
- Um administrador aprova ou bloqueia usuarios e define os niveis de acesso.
- O login exige senha e verificacao facial.
- Cada tentativa de acesso e registrada no banco de auditoria.
- Os niveis 1, 2 e 3 exibem areas com permissoes progressivas.

## Arquivos principais

- `main.py`: rotas HTTP, autenticacao, sessoes e regras de acesso.
- `database.py`: modelos e inicializacao do banco SQLite.
- `vision_pipeline.py`: pipeline de deteccao e comparacao facial.
- `bootstrap_admin.py`: criacao do primeiro administrador pela linha de comando.
- `static/`: paginas HTML, CSS e JavaScript da aplicacao.
- `requirements.txt`: dependencias Python.

## Banco e dados locais

O banco SQLite e criado na raiz com o nome `vault_security.db`. Ele e ignorado pelo Git, assim como imagens, caches Python, ambientes virtuais e arquivos `.env`.

Para reiniciar os dados locais, pare a aplicacao e remova o banco:

```bash
rm vault_security.db
```

Esse comando apaga usuarios, perfis biometricos e registros de auditoria locais.

## Configuracao de seguranca

Este projeto nao utiliza arquivo `.env`. A chave de sessao possui um valor padrao definido no codigo para facilitar a execucao local. Isso e aceitavel somente para demonstracao ou desenvolvimento local; nao use essa configuracao em um ambiente publicado.

Antes de disponibilizar o sistema em producao, substitua a chave padrao por uma configuracao segura, ative HTTPS, restrinja o cadastro publico, configure limites para imagens e trate erros internos sem devolve-los ao cliente.

Os dados biometricos e os registros de auditoria devem ser protegidos conforme as regras institucionais e a legislacao aplicavel.

## Estado do projeto

Ainda nao existem testes automatizados ou pipeline de integracao continua. As proximas melhorias recomendadas sao adicionar testes para hash de senha, autenticacao, niveis de acesso, sessao e validacao das imagens.
