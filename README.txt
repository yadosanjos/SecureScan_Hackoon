# 🛡️ SecureScan — Verificador de Segurança de Sites

O **SecureScan** é uma ferramenta web desenvolvida em Python e Flask que analisa a confiabilidade de um site com base em diversos critérios de segurança, gerando um relatório detalhado com uma pontuação de 0 a 100.

---

## 🚀 Funcionalidades

O sistema realiza uma varredura em tempo real para analisar os seguintes critérios:
* **Google Safe Browsing:** Verifica se o domínio está listado como ameaça ou phishing.
* **Presença de HTTPS:** Valida se o site utiliza protocolo de navegação segura.
* **Certificado SSL:** Checa a validade do certificado de segurança.
* **Idade do Domínio (WHOIS):** Identifica há quantos anos o domínio está registrado.
* **Headers de Segurança:** Analisa a presença de cabeçalhos de proteção essenciais (como HSTS, X-Frame-Options, etc.).
* **Informações do Servidor:** Verifica se o servidor expõe dados sensíveis.

---

## 🛠️ Tecnologias Utilizadas

Para o desenvolvimento deste projeto, utilizamos o seguinte conjunto de tecnologias:

- **Backend:** ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=flat-square&logo=flask&logoColor=white) ![Python](https://img.shields.io/badge/python-3670A0?style=flat-square&logo=python&logoColor=ffdd54)
- **Frontend:** HTML5, CSS3 (com layout responsivo, sistema de acordeão e barra de pontos).

---

## 📦 Como Instalar e Rodar o Projeto

Siga os passos abaixo para colocar o SecureScan para rodar na sua máquina local:

### 1. Clonar o repositório
```
git clone [https://github.com/seu-usuario/securescan.git](https://github.com/seu-usuario/securescan.git)
cd securescan
```

### 2. Instalar as dependências
Certifique-se de ter o Python instalado. No terminal, execute o comando abaixo para instalar todas as bibliotecas necessárias:
```
pip install flask requests python-whois python-dotenv
```

### 3. Configurar a chave da API
Copie o arquivo de exemplo e cole sua própria chave:
cp .env.example .env

Edite o .env e substitua "sua_chave_aqui" pela sua chave do Google Safe Browsing
(gere a sua em https://developers.google.com/safe-browsing/v4/get-started).

⚠️ O arquivo .env não deve ser commitado — ele já está no .gitignore.

### 4. Executar a aplicação
Para iniciar o servidor local do Flask, execute:
```
python app.py
```

-- Após rodar o comando, abra o seu navegador e acesse:
👉 `http://127.0.0.1:5000`

## 👥 Desenvolvedoras
- Laís Silva 
- Yasmin dos Anjos