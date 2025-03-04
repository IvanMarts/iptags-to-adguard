#!/usr/bin/env python3
import requests
import base64
import json
import sys
import argparse

class AdGuardAPI:
    def __init__(self, base_url: str, name: str, password: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.name = name
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._set_auth_header()
        
    def _set_auth_header(self):
        """
        Configura la cabecera Authorization con Basic Auth usando name:password.
        """
        credentials = f"{self.name}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        self.session.headers.update({
            "Authorization": f"Basic {encoded_credentials}",
            "Accept": "application/json"
        })
    
    def get_rewrite_list(self) -> dict:
        """
        Consulta el endpoint /control/rewrite/list para obtener la configuración de rewrite.
        """
        url = f"{self.base_url}/control/rewrite/list"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error obteniendo la lista de rewrite: {e}")
            sys.exit(1)
            
    def add_rewrite(self, domain: str, answer: str) -> dict:
        """
        Añade una entrada de rewrite enviando un POST al endpoint /control/rewrite/add.
        Se asume que si la respuesta es vacía pero devuelve 200, la operación fue exitosa.
        """
        url = f"{self.base_url}/control/rewrite/add"
        payload = {"domain": domain, "answer": answer}
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
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Error: {http_err} (Status Code: {response.status_code})")
            print(f"Respuesta del servidor: {response.text}")
        except Exception as e:
            print(f"Error inesperado: {e}")
        sys.exit(1)

def load_config(filename: str) -> dict:
    """
    Carga la configuración desde un fichero JSON.
    """
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading configuration file ({filename}): {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Script para administrar reglas de rewrite en AdGuard Home vía REST API"
    )
    parser.add_argument("--config", default="config.json", help="Ruta al fichero de configuración (default: config.json)")
    
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")
    
    # Subcomando list: lista la configuración de rewrite
    subparsers.add_parser("list", help="Listar la configuración de rewrite (/control/rewrite/list)")
    
    # Subcomando add: añade una entrada de rewrite
    parser_add = subparsers.add_parser("add", help="Añadir una entrada de rewrite (/control/rewrite/add)")
    parser_add.add_argument("--domain", required=True, help="Dominio para la regla de rewrite")
    parser_add.add_argument("--answer", required=True, help="Respuesta asociada al dominio")
    
    # Si no se pasan parámetros, muestra la ayuda y sale.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    config = load_config(args.config)
    adguard_url = config.get("adguard_url", "http://127.0.0.1:3000")
    name = config.get("name", "admin")
    password = config.get("password", "")
    timeout = config.get("timeout", 10)
    
    if not password:
        print("Error: El fichero de configuración debe incluir el campo 'password'.")
        sys.exit(1)
    
    api = AdGuardAPI(adguard_url, name, password, timeout)
    
    if args.command == "list":
        rewrite_config = api.get_rewrite_list()
        print("Configuración de rewrite:")
        print(json.dumps(rewrite_config, indent=2))
    elif args.command == "add":
        # Realizar una consulta previa para comprobar si ya existe la entrada.
        current_rewrites = api.get_rewrite_list()
        # Dependiendo del formato devuelto, se asume que current_rewrites es una lista,
        # o si es un dict, se busca una clave "list" o similar.
        if isinstance(current_rewrites, dict):
            # Por ejemplo, si la respuesta es {"list": [ ... ]}, usamos esa clave.
            current_rewrites = current_rewrites.get("list", current_rewrites.get("rewrite", []))
        
        exists = False
        existing_entry = None
        for entry in current_rewrites:
            if entry.get("domain") == args.domain or entry.get("answer") == args.answer:
                exists = True
                existing_entry = entry
                break
        
        if exists:
            print("No se puede añadir la entrada. Ya existe la siguiente entrada:")
            print(json.dumps(existing_entry, indent=2))
            sys.exit(0)
        else:
            result = api.add_rewrite(args.domain, args.answer)
            print("Respuesta de add rewrite:")
            print(json.dumps(result, indent=2))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
