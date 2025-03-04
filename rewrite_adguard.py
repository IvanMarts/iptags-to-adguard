#!/usr/bin/env python3
"""
Script para administrar reglas de rewrite en AdGuard Home vía REST API.

Se utilizan los siguientes endpoints:
  - GET /control/rewrite/list    : Listar reglas existentes.
  - POST /control/rewrite/add    : Agregar una nueva regla.
  - POST /control/rewrite/delete : Eliminar una regla.
  - PUT /control/rewrite/update  : Actualizar una regla.

La autenticación se realiza mediante Basic Authentication, utilizando
las credenciales definidas en el fichero de configuración (config.json).
"""

import requests
import base64
import json
import sys
import argparse
from typing import List, Dict, Optional, Any

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
        self.session: requests.Session = requests.Session()
        # Cabecera inicial para indicar contenido JSON
        self.session.headers.update({"Content-Type": "application/json"})
        self._set_auth_header()
        
    def _set_auth_header(self) -> None:
        """
        Configura la cabecera 'Authorization' utilizando Basic Authentication.
        Codifica 'name:password' en base64 y actualiza la cabecera de la sesión.
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
        Se espera que la respuesta sea una lista de diccionarios.
        """
        url: str = f"{self.base_url}/control/rewrite/list"
        try:
            response: requests.Response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            data: Any = response.json()
            # Dependiendo de la versión, la lista puede venir en la clave "list" o "rewrite".
            if isinstance(data, dict):
                return data.get("list", data.get("rewrite", []))
            return data
        except Exception as e:
            print(f"Error obteniendo la lista de rewrite: {e}")
            sys.exit(1)
            
    def add_rewrite(self, domain: str, ip: str) -> Dict[str, Any]:
        """
        Agrega una nueva regla de rewrite mediante POST a /control/rewrite/add.
        Si la respuesta es 200 pero sin contenido, se asume éxito.
        """
        url: str = f"{self.base_url}/control/rewrite/add"
        payload: Dict[str, str] = {"domain": domain, "answer": ip}
        try:
            response: requests.Response = self.session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return {"status": response.status_code, "message": response.text.strip()}
            else:
                return {"status": response.status_code, "message": "Rewrite added successfully, no content returned."}
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Error en add_rewrite: {http_err} (Status Code: {response.status_code})")
            print(f"Respuesta del servidor: {response.text}")
        except Exception as e:
            print(f"Error inesperado en add_rewrite: {e}")
        sys.exit(1)
    
    def delete_rewrite(self, domain: Optional[str] = None, ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Elimina una regla de rewrite mediante POST a /control/rewrite/delete.
        Primero se busca la entrada que coincida con el 'domain' o 'ip' proporcionado.
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
            response: requests.Response = self.session.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return {"status": response.status_code, "message": response.text.strip()}
            else:
                return {"status": response.status_code, "message": "Rewrite deleted successfully, no content returned."}
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Error en delete_rewrite: {http_err} (Status Code: {response.status_code})")
            print(f"Respuesta del servidor: {response.text}")
        except Exception as e:
            print(f"Error inesperado en delete_rewrite: {e}")
        sys.exit(1)
    
    def update_rewrite(self, target_domain: str, target_ip: str, update_domain: str, update_ip: str) -> Dict[str, Any]:
        """
        Actualiza una regla de rewrite mediante PUT a /control/rewrite/update.
        El payload enviado tiene la siguiente estructura:
        
            {
              "target": {
                "domain": target_domain,
                "answer": target_ip
              },
              "update": {
                "domain": update_domain,
                "answer": update_ip
              }
            }
        """
        url: str = f"{self.base_url}/control/rewrite/update"
        payload: Dict[str, Dict[str, str]] = {
            "target": {"domain": target_domain, "answer": target_ip},
            "update": {"domain": update_domain, "answer": update_ip}
        }
        try:
            response: requests.Response = self.session.put(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return {"status": response.status_code, "message": response.text.strip()}
            else:
                return {"status": response.status_code, "message": "Rewrite updated successfully, no content returned."}
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Error en update_rewrite: {http_err} (Status Code: {response.status_code})")
            print(f"Respuesta del servidor: {response.text}")
        except Exception as e:
            print(f"Error inesperado en update_rewrite: {e}")
        sys.exit(1)

def load_config(filename: str) -> Dict[str, Any]:
    """
    Carga la configuración desde un fichero JSON.
    """
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading configuration file ({filename}): {e}")
        sys.exit(1)

def main() -> None:
    # Configuración de argumentos del script
    parser = argparse.ArgumentParser(
        description="Script para administrar reglas de rewrite en AdGuard Home vía REST API"
    )
    parser.add_argument("--config", default="config.json", help="Ruta al fichero de configuración (default: config.json)")
    
    # Subcomandos
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")
    
    # Listado de reglas
    subparsers.add_parser("list", help="Listar la configuración de rewrite (/control/rewrite/list)")
    
    # Agregar una regla
    parser_add = subparsers.add_parser("add", help="Añadir una entrada de rewrite (/control/rewrite/add)")
    parser_add.add_argument("--domain", required=True, help="Dominio para la regla de rewrite")
    parser_add.add_argument("--ip", required=True, help="IP asociada al dominio")
    
    # Eliminar una regla
    parser_del = subparsers.add_parser("del", help="Eliminar una entrada de rewrite (/control/rewrite/delete)")
    group = parser_del.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Dominio de la entrada a eliminar")
    group.add_argument("--ip", help="IP de la entrada a eliminar")
    
    # Actualizar una regla
    parser_update = subparsers.add_parser("update", help="Actualizar una entrada de rewrite (/control/rewrite/update)")
    parser_update.add_argument("--target-domain", required=True, help="Dominio de la regla existente a actualizar")
    parser_update.add_argument("--target-ip", required=True, help="IP de la regla existente a actualizar")
    parser_update.add_argument("--update-domain", required=True, help="Nuevo dominio para la regla")
    parser_update.add_argument("--update-ip", required=True, help="Nueva IP para la regla")
    
    # Si no se pasan parámetros, mostrar ayuda
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Cargar la configuración desde el archivo JSON
    config = load_config(args.config)
    adguard_url: str = config.get("adguard_url", "http://127.0.0.1:3000")
    name: str = config.get("name", "admin")
    password: str = config.get("password", "")
    timeout: int = config.get("timeout", 10)
    
    if not password:
        print("Error: El fichero de configuración debe incluir el campo 'password'.")
        sys.exit(1)
    
    # Crear instancia de la API
    api = AdGuardAPI(adguard_url, name, password, timeout)
    
    # Ejecución de subcomandos
    if args.command == "list":
        rewrite_config = api.get_rewrite_list()
        print("Configuración de rewrite:")
        print(json.dumps(rewrite_config, indent=2))
    elif args.command == "add":
        # Si el dominio ya existe, actualizar la entrada en lugar de dar error.
        current_rewrites = api.get_rewrite_list()
        found_entry: Optional[Dict[str, Any]] = None
        for entry in current_rewrites:
            if entry.get("domain") == args.domain:
                found_entry = entry
                break
        
        if found_entry:
            print("La entrada ya existe. Se procederá a actualizarla con los nuevos datos.")
            result = api.update_rewrite(
                target_domain=args.domain,
                target_ip=found_entry.get("answer"),
                update_domain=args.domain,
                update_ip=args.ip
            )
            print("Respuesta de update rewrite:")
            print(json.dumps(result, indent=2))
        else:
            result = api.add_rewrite(args.domain, args.ip)
            print("Respuesta de add rewrite:")
            print(json.dumps(result, indent=2))
    elif args.command == "del":
        result = api.delete_rewrite(domain=args.domain, ip=args.ip)
        print("Respuesta de delete rewrite:")
        print(json.dumps(result, indent=2))
    elif args.command == "update":
        result = api.update_rewrite(
            target_domain=args.target_domain,
            target_ip=args.target_ip,
            update_domain=args.update_domain,
            update_ip=args.update_ip
        )
        print("Respuesta de update rewrite:")
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
