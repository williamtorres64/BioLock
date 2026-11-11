# BioLock

Aplicação web para controle de acesso usando senha e reconhecimento facial. O projeto foi desenvolvido em Python com FastAPI, SQLite, SQLAlchemy, OpenCV e `face_recognition`.

## Requisitos

- Python 3.10 ou mais recente
- Webcam acessível pelo navegador
- Navegador com suporte à API `getUserMedia`
- Dependências nativas necessárias pelo `dlib` para instalar o `face-recognition`

## Instalação

Clone o repositório e entre na pasta do projeto:

```bash
git clone https://github.com/williamtorres64/BioLock.git
cd BioLock
```

Crie e ative um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

No Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Instale as dependências:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Execução

Inicie o servidor em modo de desenvolvimento:

```bash
python main.py
```

Depois, acesse [http://127.0.0.1:8000](http://127.0.0.1:8000) e permita o uso da webcam.

Também é possível iniciar diretamente com o Uvicorn:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

A opção `--reload` deve ser usada apenas durante o desenvolvimento.

## Como o sistema funciona

1. O primeiro administrador é criado pelo fluxo de configuração inicial da aplicação.
2. Novas pessoas solicitam o cadastro informando seus dados, uma senha e uma referência facial.
3. Um administrador revisa os cadastros, aprova ou bloqueia contas e define o nível de acesso.
4. O login confere a senha e compara o rosto capturado com a referência cadastrada.
5. Cada tentativa de acesso é registrada no banco de auditoria.
6. Os níveis 1, 2 e 3 liberam áreas com permissões progressivas; o nível 100 é reservado à administração.

## Níveis de acesso

- **Nível 1:** área de monitoramento e informações de rotina.
- **Nível 2:** área gerencial e informações de controle.
- **Nível 3:** área restrita para protocolos de maior sensibilidade.
- **Nível 100:** painel administrativo para gerenciar usuários.

## Arquivos principais

- `main.py`: rotas da aplicação, autenticação, sessões e regras de acesso.
- `database.py`: modelos e inicialização do banco SQLite.
- `vision_pipeline.py`: etapas de detecção, extração e comparação facial.
- `static/`: páginas HTML.
- `requirements.txt`: dependências do projeto.

## Banco de dados

O banco `vault_security.db` é criado automaticamente na raiz do projeto. Ele guarda usuários, referências biométricas e registros de auditoria.

Para apagar os dados locais e começar novamente, pare a aplicação e execute:

```bash
rm vault_security.db
```

Esse comando remove usuários, perfis biométricos e registros de auditoria.

## Configuração de segurança

A chave de sessão pode ser definida pela variável de ambiente `SESSION_SECRET`:

```bash
export SESSION_SECRET="troque-esta-chave-em-um-ambiente-real"
```

Para usar cookies seguros em HTTPS, defina também:

```bash
export SESSION_COOKIE_SECURE=true
```

O valor padrão da chave existe apenas para facilitar testes locais. Em um cenário de produção real, seria utilizada uma chave própria e ativado o HTTPS.
