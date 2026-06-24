from flask import Flask, render_template, request
import requests

API_KEY = "SUA_CHAVE_AQUI"

app = Flask(__name__)

def verificar_safe_browsing(url): #safe browsing
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "hackoon",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    response = requests.post(endpoint, json=payload)
    result = response.json()

    if "matches" in result:
        return "perigoso"
    else:
        return "seguro"
    
def verificar_https(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    elif url.startswith("http://"):
        url = url.replace("http://", "https://")
    try:
        # verify=True garante que o python valide se o certificado SSL realmente funciona
        resposta = requests.get(url, timeout=5)
        return "ativo" if resposta.url.startswith("https://") else "inativo"
    except:
        return "inativo"
    

import whois
from datetime import datetime
from urllib.parse import urlparse

def verificar_idade_dominio(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        dominio = urlparse(url).netloc
        dados = whois.whois(dominio)

        data_criacao = dados.creation_date

        if isinstance(data_criacao, list):
            data_criacao = data_criacao[0]

        if not data_criacao:
            return "desconhecido", None

        idade_anos = (datetime.now() - data_criacao).days / 365

        if idade_anos >= 2:
            return "bom", idade_anos
        else:
            return "suspeito", idade_anos

    except:
        return "erro", None
    
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

def verificar_certificado(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        dominio = urlparse(url).netloc

        contexto = ssl.create_default_context()

        with socket.create_connection((dominio, 443), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()

        validade = datetime.strptime(
            cert['notAfter'],
            "%b %d %H:%M:%S %Y %Z"
        )

        dias_restantes = (validade - datetime.utcnow()).days

        if dias_restantes < 0:
            return "vencido", validade.strftime("%d/%m/%Y"), dias_restantes

        return "valido", validade.strftime("%d/%m/%Y"), dias_restantes

    except ssl.SSLCertVerificationError:
        return "invalido", None, None

    except socket.gaierror:
        return "dominio_inexistente", None, None

    except ConnectionRefusedError:
        return "sem_ssl", None, None

    except Exception as e:
        print(e)
        return "erro", None, None


@app.route("/") #lê e exibe uma página em html
def home():
    return render_template("index.html")


@app.route("/analisar", methods=["POST"]) #recebe url, testa segurança e mostra o resultado
def analisar():
    url = request.form["url"]

    status = verificar_safe_browsing(url)
    https_status = verificar_https(url)
    idade_status, idade_anos = verificar_idade_dominio(url)
    cert_status, cert_validade, dias_restantes = verificar_certificado(url)

    return render_template(
        "index.html",
        url_analisada=url,
        status=status, idade_status=idade_status, https_status=https_status, idade_anos=idade_anos,
        cert_status=cert_status,
        cert_validade=cert_validade,
        dias_restantes=dias_restantes
    )


if __name__ == "__main__":
    app.run(debug=True)