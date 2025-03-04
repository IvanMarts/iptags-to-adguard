#!/usr/bin/env python3
import requests
import base64
import json
import sys

def load_config(filename: str) -> dict:
    """Carga la configuración desde un fichero JSON."""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading configuration file ({filename}): {e}")
        sys.exit(1)

def get_status(adguard_url: str, name: str, password: str, timeout: int) -> dict:
    """
    Consulta el endpoint /control/status de AdGuard Home utilizando autenticación básica.
    Se envían las cabeceras:
      - Authorization: Basic BASE64(name:password)
      - Accept: application/json
    """
    # Codifica las credenciales en base64 para Basic Auth
    credentials = f"{name}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Accept": "application/json"
    }
    
    status_url = f"{adguard_url.rstrip('/')}/control/status"
    
    try:
        response = requests.get(status_url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error obteniendo el status: {e}")
        sys.exit(1)

def main():
    config = load_config("config.json")
    adguard_url = config.get("adguard_url", "http://127.0.0.1:3000")
    # Usamos "name" en lugar de "username"
    name = config.get("name", "admin")
    password = config.get("password", "")
    timeout = config.get("timeout", 10)
    
    if not password:
        print("Error: El fichero de configuración debe incluir el campo 'password'.")
        sys.exit(1)
    
    status_info = get_status(adguard_url, name, password, timeout)
    print("Status de AdGuard Home:")
    print(json.dumps(status_info, indent=2))

if __name__ == "__main__":
    main()
