import subprocess
import requests
import os
import ipaddress
from rich.console import Console
from rich.progress import Progress

# Crear una instancia de la consola de Rich
console = Console()

# Función para ejecutar un comando y manejar errores
def run_command(command):
    # Redirige la salida estándar y la salida de error a os.devnull
    with open(os.devnull, 'wb') as devnull:
        try:
            subprocess.run(command, check=True, shell=True, stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error al ejecutar el comando:[/red] {command}. [red]Error:[/red] {e}")

# Crear el conjunto de IPSet para listas negras si no existe
run_command("sudo ipset create blacklist hash:net -exist")

# Función para verificar si una IP ya está en el conjunto
def is_ip_in_set(ip):
    try:
        # Redirige salida estándar y de error a os.devnull
        with open(os.devnull, 'wb') as devnull:
            subprocess.run(f"sudo ipset test blacklist {ip}", check=True, shell=True, stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return False

# Función para limpiar y validar una dirección IP o rango CIDR
def clean_ip(ip):
    # Verificar si es un rango CIDR
    if '/' in ip:
        try:
            # Si es un rango CIDR, retorna el mismo (ya validado por ipaddress)
            return str(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            return None
    else:
        # Eliminar ceros a la izquierda en cada octeto
        try:
            # Limpiar y validar IP individual
            ip = '.'.join(str(int(octet)) for octet in ip.split('.') if octet.isdigit())
            return str(ipaddress.ip_address(ip))  # Cambiado a ip_address para IPs individuales
        except ValueError:
            return None

# Función para agregar una lista de IPs a IPSet
def add_to_ipset(url):
    console.print(f"[blue]Agregando IPs desde:[/blue] {url}")
    try:
        response = requests.get(url)
        lines = response.text.splitlines()
        total_ips = sum(1 for line in lines if line and not line.startswith('#'))

        with Progress() as progress:
            task = progress.add_task("[cyan]Agregando IPs...", total=total_ips)
            for line in lines:
                if line and not line.startswith('#'):
                    ip = line.split()[0].strip().split(';')[0]
                    cleaned_ip = clean_ip(ip)
                    if cleaned_ip:
                        if not is_ip_in_set(cleaned_ip):
                            run_command(f"sudo ipset add blacklist {cleaned_ip}")
                    else:
                        console.print(f"[red]IP/rango inválido:[/red] {ip}, omitiendo...")
                progress.update(task, advance=1)
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error al obtener la lista de:[/red] {url}. [red]Error:[/red] {e}")


# Función para agregar IPs manualmente desde un archivo
def add_manual_ips(file):
    if os.path.isfile(file):
        console.print(f"[blue]Agregando IPs manualmente desde el archivo:[/blue] {file}")
        with open(file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    cleaned_ip = clean_ip(ip)  # Limpia y valida la IP o rango CIDR
                    if cleaned_ip:
                        if not is_ip_in_set(cleaned_ip):
                            run_command(f"sudo ipset add blacklist {cleaned_ip}")
                        else:
                            console.print(f"La IP/rango [yellow]{cleaned_ip}[/yellow] ya existe en el conjunto, omitiendo...")
                    else:
                        console.print(f"[red]IP/rango inválido:[/red] {ip}, omitiendo...")
    else:
        console.print(f"[red]El archivo {file} no existe.[/red]")

# Eliminar reglas anteriores de iptables para el conjunto de blacklist
console.print("[blue]Eliminando reglas anteriores de iptables para blacklist...[/blue]")
run_command("sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null")

# Aplicar la regla en iptables para bloquear el conjunto completo
console.print("[blue]Aplicando la nueva regla en iptables...[/blue]")
run_command("sudo iptables -I INPUT -m set --match-set blacklist src -j DROP")

# Agregar las listas
urls = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    "https://www.dshield.org/ipsascii.html?limit=10000",
    "http://cinsscore.com/list/ci-badguys.txt"
]

for url in urls:
    add_to_ipset(url)

# Agregar IPs manuales desde el archivo
add_manual_ips("manual_blacklist.txt")

console.print("[green]Proceso completado.[/green]")
