"""
Security validators for Anisakys.
Prevents command injection, path traversal, and other security vulnerabilities.
"""

import os
import re
from pathlib import Path
from typing import Optional


def validate_domain(domain: str) -> bool:
    """
    Valida nombre de dominio para prevenir command injection.

    Args:
        domain: Nombre de dominio a validar

    Returns:
        True si es válido

    Raises:
        ValueError: Si el dominio es inválido
    """
    # RFC 1035 compliant domain validation
    pattern = r'^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$'

    if not domain or len(domain) > 253:
        raise ValueError(f"Invalid domain length: {len(domain)}")

    if not re.match(pattern, domain):
        raise ValueError(f"Invalid domain format: {domain}")

    # Caracteres peligrosos que nunca deben estar en un dominio
    dangerous_chars = ['`', '$', '(', ')', ';', '|', '&', '<', '>', '\n', '\r']
    if any(char in domain for char in dangerous_chars):
        raise ValueError(f"Domain contains dangerous characters: {domain}")

    return True


def validate_whois_server(server: str) -> bool:
    """
    Valida hostname de servidor WHOIS.

    Args:
        server: Hostname del servidor WHOIS

    Returns:
        True si es válido

    Raises:
        ValueError: Si el servidor es inválido
    """
    # Debe ser un hostname válido
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'

    if not re.match(pattern, server):
        raise ValueError(f"Invalid WHOIS server: {server}")

    return True


def safe_join(base_dir: str, user_path: str) -> Path:
    """
    Une paths de forma segura previniendo path traversal.

    Args:
        base_dir: Directorio base (confiable)
        user_path: Componente de path provisto por usuario

    Returns:
        Path resuelto seguro

    Raises:
        ValueError: Si se detecta path traversal
    """
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()

    # Asegurar que target está dentro de base directory
    try:
        target.relative_to(base)
    except ValueError:
        raise ValueError(f"Path traversal attempt detected: {user_path}")

    return target


def sanitize_filename(filename: str, max_length: int = 200) -> str:
    """
    Sanitiza filename para uso seguro en filesystem.

    Args:
        filename: Nombre de archivo original
        max_length: Longitud máxima del filename

    Returns:
        Filename sanitizado
    """
    # Remover todo excepto alfanuméricos, underscore, dash, y punto
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)

    # Remover puntos iniciales (archivos ocultos)
    clean = clean.lstrip('.')

    # Limitar longitud
    if len(clean) > max_length:
        name, ext = os.path.splitext(clean)
        clean = name[:max_length - len(ext)] + ext

    return clean or 'unnamed'
