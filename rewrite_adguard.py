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
        Configura la cabecera Authorization usando Basic Auth con name:password.
        """
        credentials = f"{self.name}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        self.session.headers.update({
            "Authorization": f"Basic {encoded_credentials}",
            "Accept": "application/json"
        })
    
    def get_rewrite_list(self) -> list:
        """
        Consulta el endpoint /control/rewrite/list para obtener la configuración de rewrite.
        Se espera que la respuesta contenga una lista de reglas.
        """
        url = f"{self.base_url}/control/rewrite/list"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                return data.get("list", data.get("rewrite", []))
            return data
        except Exception as e:
            print(f"Error obteniendo la lista de rewrite: {e}")
            sys.exit(1)
            
    def add_rewrite(self, domain: str, ip: str) -> dict:
        """
        Añade una entrada de rewrite enviando un POST al endpoint /control/rewrite/add.
        Se asume que si la respuesta es vacía pero devuelve 200, la operación fue exitosa.
        """
        url = f"{self.base_url}/control/rewrite/add"
        payload = {"domain": domain, "answer": ip}
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
    
    def delete_rewrite(self, domain: str = None, ip: str = None) -> dict:
        """
        Elimina una entrada de rewrite enviando un POST al endpoint /control/rewrite/delete.
        Se busca primero en la lista una regla que coincida con el domain o ip indicado.
        """
        current_rewrites = self.get_rewrite_list()
        found_entry = None
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
        
        url = f"{self.base_url}/control/rewrite/delete"
        payload = {
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
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP Error: {http_err} (Status Code: {response.status_code})")
            print(f"Respuesta del servidor: {response.text}")
        except Exception as e:
            print(f"Error inesperado: {e}")
        sys.exit(1)
    
    def update_rewrite(self, target_domain: str, target_ip: str, update_domain: str, update_ip: str) -> dict:
        """
        Actualiza una regla de rewrite enviando un PUT al endpoint /control/rewrite/update.
        El payload tiene la forma:
        
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
        url = f"{self.base_url}/control/rewrite/update"
        payload = {
            "target": {
                "domain": target_domain,
                "answer": target_ip
            },
            "update": {
                "domain": update_domain,
                "answer": update_ip
            }
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
    parser_add.add_argument("--ip", required=True, help="IP asociada al dominio")
    
    # Subcomando del: elimina una entrada de rewrite
    parser_del = subparsers.add_parser("del", help="Eliminar una entrada de rewrite (/control/rewrite/delete)")
    group = parser_del.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="Dominio de la entrada a eliminar")
    group.add_argument("--ip", help="IP de la entrada a eliminar")
    
    # Subcomando update: actualiza una entrada de rewrite
    parser_update = subparsers.add_parser("update", help="Actualizar una entrada de rewrite (/control/rewrite/update)")
    parser_update.add_argument("--target-domain", required=True, help="Dominio de la regla existente a actualizar")
    parser_update.add_argument("--target-ip", required=True, help="IP de la regla existente a actualizar")
    parser_update.add_argument("--update-domain", required=True, help="Nuevo dominio para la regla")
    parser_update.add_argument("--update-ip", required=True, help="Nueva IP para la regla")
    
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
        # Se busca si ya existe una entrada con el mismo dominio.
        current_rewrites = api.get_rewrite_list()
        found_entry = None
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
