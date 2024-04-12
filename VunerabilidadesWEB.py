import nmap
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import sys

def get_ip_address(url):
    try:
        ip_address = socket.gethostbyname(url)
        print(f'O endereço IP associado a {url} é: {ip_address}')
    except socket.gaierror:
        print(f'Não foi possível encontrar o endereço IP para {url}')

def scan_network(target):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments='-p 1-65535 --open')  # Escaneia todas as portas abertas

        for host in scanner.all_hosts():
            print('----------------------------------------------------')
            print(f'Host : {host} ({scanner[host].hostname()})')
            print('State :', scanner[host].state())

            for proto in scanner[host].all_protocols():
                print('----------')
                print(f'Protocol : {proto}')

                ports = scanner[host][proto].keys()
                for port in ports:
                    print(f'Port : {port}\tState : {scanner[host][proto][port]["state"]}')
    except Exception as e:
        print(f"Ocorreu um erro ao escanear a rede: {e}")

def check_web_vulnerabilities(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f'O site {url} está acessível e parece estar funcionando normalmente.')
        else:
            print(f'O site {url} pode estar inacessível ou enfrentando problemas.')

        if "error in your SQL syntax" in response.text:
            print(f'O site {url} parece ser vulnerável a injeção de SQL.')
        else:
            print(f'O site {url} não parece ser vulnerável a injeção de SQL.')

        if "<script>" in response.text:
            print(f'O site {url} parece ser vulnerável a Cross-Site Scripting (XSS).')
        else:
            print(f'O site {url} não parece ser vulnerável a Cross-Site Scripting (XSS).')

        soup = BeautifulSoup(response.content, 'html.parser')
        forms = soup.find_all('form')
        csrf_vulnerable = False
        
        for form in forms:
            csrf_token_input = form.find('input', {'name': 'csrf_token'})
            if csrf_token_input:
                csrf_vulnerable = True
                break
        
        if csrf_vulnerable:
            print(f'O site {url} parece ser vulnerável a Cross-Site Request Forgery (CSRF).')
        else:
            print(f'O site {url} não parece ser vulnerável a Cross-Site Request Forgery (CSRF).')

        # Verificação do SSL/TLS
        try:
            cert = ssl.get_server_certificate((url, 443))
            x509 = ssl.PEM_cert_to_DER_cert(cert)
            print(f"O site {url} utiliza SSL/TLS e o certificado é válido.")
        except Exception as e:
            print(f"O site {url} não utiliza SSL/TLS ou o certificado é inválido.")
        
        # Verificação de Headers HTTP
        try:
            response = requests.get(url)
            headers = response.headers
            if 'Content-Security-Policy' in headers:
                print(f"Content-Security-Policy: {headers['Content-Security-Policy']}")
            else:
                print("Content-Security-Policy não está definido.")

            if 'Strict-Transport-Security' in headers:
                print(f"Strict-Transport-Security: {headers['Strict-Transport-Security']}")
            else:
                print("Strict-Transport-Security não está definido.")
        except Exception as e:
            print(f"Erro ao verificar headers HTTP: {e}")

        # Varredura de Diretórios do Site
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                links = soup.find_all('a')
                print("Diretórios encontrados:")
                for link in links:
                    href = link.get('href')
                    if href.startswith('/'):
                        print(href)
        except Exception as e:
            print(f"Erro ao varrer diretórios do site: {e}")

        # Análise de Tecnologias Utilizadas
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                meta_tags = soup.find_all('meta')
                technologies = set()
                for tag in meta_tags:
                    if tag.get('name') == 'generator':
                        technologies.add(tag.get('content'))
                if technologies:
                    print("Tecnologias utilizadas:")
                    for tech in technologies:
                        print(tech)
                else:
                    print("Nenhuma tecnologia identificada.")
        except Exception as e:
            print(f"Erro ao identificar tecnologias utilizadas: {e}")

    except Exception as e:
        print(f"Ocorreu um erro ao verificar as vulnerabilidades do site: {e}")

# Solicitar ao usuário que insira o URL do site que deseja verificar
try:
    site_url = input("Insira o URL do site que deseja verificar: ")
    scan_network('192.168.0.1/24')  # Substitua pelo intervalo de IP que deseja escanear
    check_web_vulnerabilities(site_url)
except KeyboardInterrupt:
    print("\nOperação interrompida pelo usuário.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")
