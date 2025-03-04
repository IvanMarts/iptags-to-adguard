#!/usr/bin/env python3
"""
Script para extraer los tags de VMs y contenedores (LXC) en Proxmox y actualizar las reglas de rewrite
en AdGuard Home vía REST API.

Se ejecuta en el host de Proxmox (donde están disponibles los comandos qm y pct).

La configuración de AdGuard se carga desde un fichero JSON (por defecto config.json) con este formato:
{
  "adguard_url": "http://192.168.1.1:83",
  "name": "your_username",
  "password": "your_password",
  "timeout": 10,
  "allowed_cidrs": [
    "192.168.0.0/16",
    "100.64.0.0/10",
    "10.0.0.0/8"
  ],
  "network_domain": "dominio"
}
Si network_domain es "dominio", un host llamado "vm01" se actualizará como "vm01.dominio".
"""

import subprocess
import re
import ipaddress
import json
import sys
import argparse
from typing import List, Dict, Any, Optional

# Global variable para los CIDRs permitidos (se configurarán desde el fichero de configuración).
ALLOWED_CIDRS: List[ipaddress.IPv4Network] = []

# -----------------------------
# Clase para interactuar con la API de AdGuard Home (Rewrite)
# -----------------------------
import requests, base64

class AdGuardAPI:
    def __init__(self, base_url: str, name: str, password: str, timeout: int = 10) -> None:
        """
        Inicializa la instancia con la URL base, credenciales y timeout.
        Se establece la sesión HTTP y se configuran las cabeceras.
        """
        self.base_url: str = base_url.rstrip("/")
        self.name: str = name
        self.password: str = password
        self.timeout: int = timeout
        self.session = requests.Session()
        # Indica que se envía JSON
        self.session.headers.update({"Content-Type": "application/json"})
        self._set_auth_header()
        
    def _set_auth_header(self) -> None:
        """
        Configura la cabecera 'Authorization' utilizando Basic Auth.
        """
        credentials: str = f"{self.name}:{self.password}"
        encoded_credentials: str = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        self.session.headers.update({
            "Authorization": f"Basic {encoded_credentials}",
            "Accept": "application/json"
        })
    
    def get_rewrite_list(self) -> List[Dict[str, Any]]:
        """
        Consulta el endpoint /control/rewrite/list para obtener la lista de reglas.
        Se espera una respuesta con una lista de diccionarios.
        """
        url: str = f"{self.base_url}/control/rewrite/list"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            data: Any = response.json()
            # La respuesta puede venir en la clave "list" o "rewrite"
            if isinstance(data, dict):
                return data.get("list", data.get("rewrite", []))
            return data
        except Exception as e:
            print(f"Error obteniendo la lista de rewrite: {e}")
            sys.exit(1)
            
    def add_rewrite(self, domain: str, ip: str) -> Dict[str, Any]:
        """
        Agrega una nueva regla de rewrite mediante POST a /control/rewrite/add.
        Si la respuesta es 200 sin contenido, se asume éxito.
        """
        url: str = f"{self.base_url}/control/rewrite/add"
        payload: Dict[str, str] = {"domain": domain, "answer": ip}
        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return {"status": response.status_code, "message": response.text.strip()}
            else:
                return {"status": response.status_code, "message": "Rewrite added successfully, no content returned."}
        except Exception as e:
            print(f"Error en add_rewrite: {e}")
            sys.exit(1)
    
    def update_rewrite(self, target_domain: str, target_ip: str, update_domain: str, update_ip: str) -> Dict[str, Any]:
        """
        Actualiza una regla de rewrite mediante PUT a /control/rewrite/update.
        El payload enviado tiene la siguiente estructura:
        
            {
              "target": { "domain": target_domain, "answer": target_ip },
              "update": { "domain": update_domain, "answer": update_ip }
            }
        """
        url: str = f"{self.base_url}/control/rewrite/update"
        payload: Dict[str, Dict[str, str]] = {
            "target": {"domain": target_domain, "answer": target_ip},
            "update": {"domain": update_domain, "answer": update_ip}
        }
        try:
            response = self.session.put(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return {"status": response.status_code, "message": response.text.strip()}
            else:
                return {"status": response.status_code, "message": "Rewrite updated successfully, no content returned."}
        except Exception as e:
            print(f"Error en update_rewrite: {e}")
            sys.exit(1)

    def delete_rewrite(self, domain: Optional[str] = None, ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Elimina una regla de rewrite mediante POST a /control/rewrite/delete.
        Primero busca en la lista una regla que coincida con el domain o ip indicado.
        """
        current_rewrites: List[Dict[str, Any]] = self.get_rewrite_list()
        found_entry: Optional[Dict[str, Any]] = None
        for entry in current_rewrites:
            if domain and entry.get("domain") == domain:
                found_entry = entry
                break
            if ip and entry.get("answer") == ip:
                found_entry = entry
                break
        
        if not found_entry:
            print("No se encontró ninguna entrada que coincida con los criterios dados.")
            sys.exit(0)
        
        url: str = f"{self.base_url}/control/rewrite/delete"
        payload: Dict[str, str] = {
            "domain": found_entry.get("domain"),
            "answer": found_entry.get("answer")
        }
        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return {"status": response.status_code, "message": response.text.strip()}
            else:
                return {"status": response.status_code, "message": "Rewrite deleted successfully, no content returned."}
        except Exception as e:
            print(f"Error en delete_rewrite: {e}")
            sys.exit(1)

# -----------------------------
# Funciones auxiliares para procesar IPs y hostnames
# -----------------------------
def is_valid_ip(ip: str) -> bool:
    """
    Comprueba si la IP es válida y se encuentra en alguno de los CIDRs permitidos.
    Usa la variable global ALLOWED_CIDRS.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in ALLOWED_CIDRS:
            # # DEBUG: print(f"DEBUG: Verificando si {ip_obj} está en {net}")
            if ip_obj in net:
                # # DEBUG: print(f"DEBUG: {ip_obj} se encuentra en {net}")
                return True
        # # DEBUG: print(f"DEBUG: {ip_obj} no se encontró en ningún CIDR permitido.")
        return False
    except Exception as e:
        # # DEBUG: print(f"DEBUG: Error en is_valid_ip al procesar '{ip}': {e}")
        return False

def sanitize_hostname(host: str) -> str:
    """
    Convierte el hostname a minúsculas y elimina caracteres no permitidos (solo a-z, 0-9 y guiones).
    """
    return re.sub(r'[^a-z0-9-]', '', host.lower())

def extract_valid_ip(tags: str) -> str:
    """
    Extrae la primera dirección IP encontrada en la cadena de tags.
    Busca cualquier secuencia que se parezca a una IPv4 y la valida.
    """
    # # DEBUG: print(f"DEBUG: Procesando tags: '{tags}'")
    candidates = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', tags)
    # # DEBUG: print(f"DEBUG: Candidatos encontrados: {candidates}")
    for candidate in candidates:
        # # DEBUG: print(f"DEBUG: Procesando candidato: '{candidate}'")
        try:
            ip_obj = ipaddress.ip_address(candidate)
            # # DEBUG: print(f"DEBUG: '{candidate}' es una IP válida: {ip_obj}")
            if is_valid_ip(candidate):
                # # DEBUG: print(f"DEBUG: La IP '{candidate}' es válida y está dentro de los CIDRs permitidos.")
                return candidate
        except ValueError as e:
            # # DEBUG: print(f"DEBUG: Error al convertir '{candidate}' en IP: {e}")
            continue
    # # DEBUG: print("DEBUG: No se encontró ninguna IP válida en los tags.")
    return ""

# -----------------------------
# Funciones para ejecutar comandos de Proxmox
# -----------------------------
def get_running_vmids() -> List[str]:
    """
    Ejecuta 'qm list' y devuelve una lista de VMIDs de VMs en estado "running".
    """
    try:
        output = subprocess.check_output(["qm", "list"], universal_newlines=True)
        lines = output.strip().splitlines()
        vmids = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2].lower() == "running":
                vmids.append(parts[0])
        return vmids
    except Exception as e:
        print("Error obteniendo lista de VMs:", e)
        return []

def get_running_lxc_ids() -> List[str]:
    """
    Ejecuta 'pct list' y devuelve una lista de IDs de contenedores en estado "running".
    """
    try:
        output = subprocess.check_output(["pct", "list"], universal_newlines=True)
        lines = output.strip().splitlines()
        lxcids = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1].lower() == "running":
                lxcids.append(parts[0])
        return lxcids
    except Exception as e:
        print("Error obteniendo lista de LXC:", e)
        return []

def get_vm_config(vmid: str) -> List[str]:
    """
    Ejecuta 'qm config <vmid>' y devuelve la salida como lista de líneas.
    """
    try:
        output = subprocess.check_output(["qm", "config", vmid], universal_newlines=True)
        return output.strip().splitlines()
    except Exception as e:
        print(f"Error obteniendo configuración para VM {vmid}: {e}")
        return []

def get_lxc_config(lxcid: str) -> List[str]:
    """
    Ejecuta 'pct config <lxcid>' y devuelve la salida como lista de líneas.
    """
    try:
        output = subprocess.check_output(["pct", "config", lxcid], universal_newlines=True)
        return output.strip().splitlines()
    except Exception as e:
        print(f"Error obteniendo configuración para LXC {lxcid}: {e}")
        return []

def extract_value_from_config(lines: List[str], key: str) -> str:
    """
    Busca en las líneas de configuración la línea que comience con el 'key' y devuelve el valor.
    Ejemplo: Para key "name:" devuelve el contenido después de los dos puntos.
    """
    for line in lines:
        if line.startswith(key):
            parts = line.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip()
    return ""

# -----------------------------
# Función principal
# -----------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Script para actualizar reglas de rewrite en AdGuard Home a partir de tags de Proxmox"
    )
    parser.add_argument("--config", default="config.json",
                        help="Ruta al fichero de configuración de AdGuard (default: config.json)")
    args = parser.parse_args()

    # Cargar la configuración de AdGuard desde el fichero externo.
    try:
        with open(args.config, "r") as f:
            ag_config = json.load(f)
    except Exception as e:
        print("Error cargando configuración de AdGuard:", e)
        sys.exit(1)

    adguard_url: str = ag_config.get("adguard_url", "http://127.0.0.1:3000")
    ag_name: str = ag_config.get("name", "admin")
    ag_password: str = ag_config.get("password", "")
    timeout: int = ag_config.get("timeout", 10)
    network_domain: str = ag_config.get("network_domain", "")
    if not ag_password:
        print("Error: El fichero de configuración debe incluir 'password'.")
        sys.exit(1)

    # Configurar ALLOWED_CIDRS desde el fichero de configuración.
    cidr_list = ag_config.get("allowed_cidrs", ["192.168.0.0/16", "100.64.0.0/10", "10.0.0.0/8"])
    global ALLOWED_CIDRS
    try:
        ALLOWED_CIDRS = [ipaddress.ip_network(cidr) for cidr in cidr_list]
    except Exception as e:
        print(f"Error procesando 'allowed_cidrs' en la configuración: {e}")
        sys.exit(1)

    # Crear instancia de la API de AdGuard.
    api = AdGuardAPI(adguard_url, ag_name, ag_password, timeout)

    # Procesar VMs (QEMU).
    print("Procesando VMs (QEMU)...")
    vmids: List[str] = get_running_vmids()
    for vmid in vmids:
        config_lines: List[str] = get_vm_config(vmid)
        vmname: str = extract_value_from_config(config_lines, "name:")
        vmname = sanitize_hostname(vmname)
        # Agregar el dominio de red si está definido y no está presente
        if network_domain and not vmname.endswith("." + network_domain):
            vmname = f"{vmname}.{network_domain}"
        tags: str = extract_value_from_config(config_lines, "tags:")
        tag_ip: str = extract_valid_ip(tags)
        if vmname and tag_ip:
            print(f"VM {vmid}: {vmname} -> {tag_ip}")
            current_rewrites: List[Dict[str, Any]] = api.get_rewrite_list()
            found_entry: Optional[Dict[str, Any]] = None
            for entry in current_rewrites:
                if entry.get("domain") == vmname:
                    found_entry = entry
                    break
            if found_entry:
                print(f"La entrada para {vmname} ya existe; se actualizará.")
                result = api.update_rewrite(
                    target_domain=vmname,
                    target_ip=found_entry.get("answer"),
                    update_domain=vmname,
                    update_ip=tag_ip
                )
                print("Resultado de update:", json.dumps(result, indent=2))
            else:
                result = api.add_rewrite(vmname, tag_ip)
                print("Resultado de add:", json.dumps(result, indent=2))
        else:
            print(f"No se encontró tag válido para la VM {vmid}")

    # Procesar contenedores (LXC).
    print("Procesando contenedores (LXC)...")
    lxcids: List[str] = get_running_lxc_ids()
    for lxcid in lxcids:
        config_lines = get_lxc_config(lxcid)
        hostname: str = extract_value_from_config(config_lines, "hostname:")
        hostname = sanitize_hostname(hostname)
        if network_domain and not hostname.endswith("." + network_domain):
            hostname = f"{hostname}.{network_domain}"
        tags: str = extract_value_from_config(config_lines, "tags:")
        tag_ip: str = extract_valid_ip(tags)
        if hostname and tag_ip:
            print(f"LXC {lxcid}: {hostname} -> {tag_ip}")
            current_rewrites = api.get_rewrite_list()
            found_entry = None
            for entry in current_rewrites:
                if entry.get("domain") == hostname:
                    found_entry = entry
                    break
            if found_entry:
                print(f"La entrada para {hostname} ya existe; se actualizará.")
                result = api.update_rewrite(
                    target_domain=hostname,
                    target_ip=found_entry.get("answer"),
                    update_domain=hostname,
                    update_ip=tag_ip
                )
                print("Resultado de update:", json.dumps(result, indent=2))
            else:
                result = api.add_rewrite(hostname, tag_ip)
                print("Resultado de add:", json.dumps(result, indent=2))
        else:
            print(f"No se encontró tag válido para el LXC {lxcid}")

if __name__ == "__main__":
    main()
