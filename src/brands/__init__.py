"""Brand catalogue: brands added from the console, merged with the built-in list for detection."""

from src.brands.catalog import current_catalog, invalidate
from src.brands.repository import (
    BrandConflictError,
    BrandNotFoundError,
    BrandRecord,
    BrandRepository,
    BrandValidationError,
    validate_brand,
)

__all__ = [
    "BrandConflictError",
    "BrandNotFoundError",
    "BrandRecord",
    "BrandRepository",
    "BrandValidationError",
    "current_catalog",
    "invalidate",
    "validate_brand",
]
