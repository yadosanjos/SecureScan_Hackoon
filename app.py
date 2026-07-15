from flask import Flask, render_template, request, session, redirect, url_for
import requests
import socket

from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

app = Flask(__name__)

app.secret_key = "chaveSecreta"

def dominio_existe(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        dominio = urlparse(url).netloc
        socket.gethostbyname(dominio)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return True

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

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()

        if "matches" in result:
            return "perigoso"
        else:
            return "seguro"
    except Exception as e:
        print("ERRO Safe Browsing:", e)
        return "desconhecido"
    
def verificar_https(url):
    url = url.strip()
    url_teste = url.lower()

    if not url_teste.startswith(("http://", "https://")):
        url = "https://" + url
    elif url_teste.startswith("http://"):
        url = "https://" + url[7:]

    try:
        resposta = requests.get(url, timeout=5)
        if resposta.url.startswith("https://"):
            return "ativo"
        else:
            return "inativo"
    except:
        return "inativo"
    

import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

def verificar_idade_dominio(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        dominio = urlparse(url).netloc.replace("www.", "")

        if dominio.endswith(".br"):
            endpoint = f"https://rdap.registro.br/domain/{dominio}"
        else:
            endpoint = f"https://rdap.org/domain/{dominio}"

        resposta = requests.get(endpoint, timeout=5)

        if resposta.status_code != 200:
            return "desconhecido", None

        dados = resposta.json()

        data_criacao = None
        for evento in dados.get("events", []):
            if evento.get("eventAction") == "registration":
                data_criacao = evento.get("eventDate")
                break

        if not data_criacao:
            return "desconhecido", None

        data_criacao_dt = datetime.fromisoformat(data_criacao.replace("Z", "+00:00"))
        agora = datetime.now(timezone.utc)

        idade_anos = (agora - data_criacao_dt).days / 365

        if idade_anos >= 2:
            return "bom", idade_anos
        else:
            return "suspeito", idade_anos

    except Exception as e:
        print("ERRO RDAP:", e)
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

    except (ConnectionRefusedError, socket.timeout):
        return "sem_ssl", None, None

    except Exception as e:
        print(e)
        return "erro", None, None
    
def verificar_headers(url):     # pontos vai de 0 a 25
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    detalhes_padrao = {
        "hsts": ("ausente", None),
        "csp": ("ausente", None),
        "clickjacking": ("desprotegido", None),
        "xcto": ("ausente", None),
        "referrer_policy": ("ausente", None),
        "permissions_policy": ("ausente", None),
    }

    try:
        try:
            headers_request = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/138.0 Safari/537.36"
                )
            }

            resposta = requests.get(
                url,
                headers=headers_request,
                timeout=5,
                allow_redirects=True
            )
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
            url_http = url.replace("https://", "http://")
            resposta = requests.get(
                url_http,
                headers=headers_request,
                timeout=5,
                allow_redirects=True
            )
        headers = resposta.headers

        pontos = 0
        detalhes = {}

        # HSTS - 6 pts
        hsts = headers.get("Strict-Transport-Security")
        if hsts:
            pontos += 6
            detalhes["hsts"] = ("presente", hsts)
        else:
            detalhes["hsts"] = ("ausente", None)

        # CSP - 8 pts (parcial se tiver unsafe-inline/unsafe-eval liberado)
        csp = headers.get("Content-Security-Policy")
        if csp:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                pontos += 4
                detalhes["csp"] = ("presente_fraco", csp)
            else:
                pontos += 8
                detalhes["csp"] = ("presente", csp)
        else:
            detalhes["csp"] = ("ausente", None)

        # X-Frame-Options ou frame-ancestors no CSP - 4 pts
        xfo = headers.get("X-Frame-Options")
        frame_ancestors = csp and "frame-ancestors" in csp
        if xfo or frame_ancestors:
            pontos += 4
            detalhes["clickjacking"] = ("protegido", xfo or "frame-ancestors no CSP")
        else:
            detalhes["clickjacking"] = ("desprotegido", None)

        # X-Content-Type-Options - 3 pts
        xcto = headers.get("X-Content-Type-Options")
        if xcto and xcto.lower() == "nosniff":
            pontos += 3
            detalhes["xcto"] = ("presente", xcto)
        else:
            detalhes["xcto"] = ("ausente", None)

        # Referrer-Policy - 2 pts
        rp = headers.get("Referrer-Policy")
        if rp:
            pontos += 2
            detalhes["referrer_policy"] = ("presente", rp)
        else:
            detalhes["referrer_policy"] = ("ausente", None)

        # Permissions-Policy - 2 pts
        pp = headers.get("Permissions-Policy")
        if pp:
            pontos += 2
            detalhes["permissions_policy"] = ("presente", pp)
        else:
            detalhes["permissions_policy"] = ("ausente", None)

        return pontos, detalhes  

    except Exception as e:
        print("ERRO headers:", type(e).__name__, e)
        return 0, detalhes_padrao
    
def verificar_servidor(url):    # pontos vai de 0 a 10
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    detalhes_erro = {
        "server_header": ("erro", "não informado"),
        "x_powered_by": ("erro", None),
    }

    try:
        try:
            headers_request = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/138.0 Safari/537.36"
                )
            }

            resposta = requests.get(
                url,
                headers=headers_request,
                timeout=5,
                allow_redirects=True
            )
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
            url_http = url.replace("https://", "http://")
            resposta = requests.get(url_http, timeout=5)

        server_header = resposta.headers.get("Server", "")
        powered_by = resposta.headers.get("X-Powered-By", "")

        pontos = 0
        detalhes = {}

        # Server não expõe versão detalhada - 5 pts
        expoe_versao = any(char.isdigit() for char in server_header)
        if not server_header or not expoe_versao:
            pontos += 5
            detalhes["server_header"] = ("oculto", server_header or "não informado")
        else:
            detalhes["server_header"] = ("exposto", server_header)

        # X-Powered-By não presente (também vaza stack) - 5 pts
        if not powered_by:
            pontos += 5
            detalhes["x_powered_by"] = ("oculto", None)
        else:
            detalhes["x_powered_by"] = ("exposto", powered_by)

        return pontos, detalhes 

    except Exception as e:
        print("ERRO servidor:", type(e).__name__, e)
        return 0, detalhes_erro

def calcular_pontuacao(safe_status, https_status, cert_status, dias_restantes,
                        idade_status, pontos_headers, pontos_servidor):

    # --- Safe Browsing: 30 pts + corte crítico ---
    pontos_safe = 30 if safe_status == "seguro" else 0

    # --- HTTPS ---
    pontos_https = 10 if https_status == "ativo" else 0

    # --- SSL: 25 pts ---
    pontos_ssl = 0
    if https_status == "ativo" and cert_status == "valido":
        pontos_ssl = 10 + (5 if dias_restantes and dias_restantes > 30 else 2)

    # --- Idade do domínio: 10 pts ---
    pontos_idade = {"bom": 10, "suspeito": 4}.get(idade_status, 2)

    total = (pontos_safe + pontos_https + pontos_ssl + pontos_headers +
              pontos_idade + pontos_servidor)

    # --- Corte crítico: Safe Browsing perigoso trava o score ---
    if safe_status != "seguro":
        total = min(total, 15)

    total = max(0, min(100, total))

    if total >= 90:
        classificacao = "Excelente"
    elif total >= 70:
        classificacao = "Bom"
    elif total >= 50:
        classificacao = "Regular"
    elif total >= 25:
        classificacao = "Fraco"
    else:
        classificacao = "Crítico"
    
    pontos_detalhes = {
        "safe_browsing": pontos_safe,
        "https": pontos_https,
        "ssl": pontos_ssl,
        "idade": pontos_idade,
    }

    return total, classificacao, pontos_detalhes


@app.route("/") #lê e exibe uma página em html
def home():
    return render_template(
        "index.html",
        historico=session.get("historico", [])
    )


@app.route("/analisar", methods=["POST"]) #recebe url, testa segurança e mostra o resultado
def analisar():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for("home"))
    
    if not dominio_existe(url):
        return render_template(
            "index.html",
            erro_dominio=True,
            url_analisada=url,
            historico=session.get("historico", [])
        )

    historico = session.get("historico", []) # começo do histórico
    if url in historico:
        historico.remove(url)
    historico.insert(0, url)
    historico = historico[:5]
    session["historico"] = historico

    status = verificar_safe_browsing(url)
    https_status = verificar_https(url)
    idade_status, idade_anos = verificar_idade_dominio(url)
    cert_status, cert_validade, dias_restantes = verificar_certificado(url)
    pontos_headers, headers_detalhes = verificar_headers(url)
    pontos_servidor, servidor_detalhes = verificar_servidor(url)

    score, classificacao, pontos_detalhes = calcular_pontuacao(
        status, https_status, cert_status, dias_restantes,
        idade_status, pontos_headers, pontos_servidor
    )

    return render_template(
        "index.html",
        url_analisada=url,
        status=status, idade_status=idade_status, https_status=https_status, idade_anos=idade_anos,
        cert_status=cert_status,
        cert_validade=cert_validade,
        dias_restantes=dias_restantes, 
        pontos_headers=pontos_headers,
        headers_detalhes=headers_detalhes,
        servidor_detalhes=servidor_detalhes, score=score, 
        classificacao=classificacao, 
        pontos_servidor=pontos_servidor,
        pontos_detalhes=pontos_detalhes,
        historico=session.get("historico", [])
    )


if __name__ == "__main__":
    app.run(debug=True)