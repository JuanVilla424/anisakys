"""Image fingerprints for brand assets, favicons and screenshots (phase 2).

* ``phash`` — perceptual hash: 32x32 greyscale, 2-D DCT, the 8x8 lowest frequencies
  thresholded at their median (64 bits, 16 hex digits). Robust to resizing and recompression.
* ``dhash`` — difference hash: 9x8 greyscale, each pixel compared with its right neighbour.
* ``favicon_mmh3`` — the Shodan-style favicon hash: MurmurHash3 (32-bit, signed) of the
  base64 encoding with a newline every 76 characters. Exact match = the same file, and it
  matches what Shodan/Censys report (``http.favicon.hash``).
* ``hamming`` — distance between two hex hashes (0 = identical; <= 10 of 64 bits is usually
  the same picture).

Images come from attacker-controlled pages: :func:`load_image` caps the bytes and the pixel
count (decompression bombs) and accepts only raster formats Pillow decodes.
"""

from __future__ import annotations

import base64
import hashlib
import io
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import mmh3
import numpy as np
from PIL import Image, UnidentifiedImageError

MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
_HASH_SIZE = 8
_DCT_SIZE = 32


class ImageRejected(ValueError):
    """The bytes are not an acceptable raster image."""


@dataclass(frozen=True)
class Fingerprint:
    """Hashes of one image."""

    sha256: str
    phash: str
    dhash: str
    width: int
    height: int


def load_image(data: bytes) -> Image.Image:
    """Decode an untrusted image safely.

    Args:
        data: Image bytes.

    Returns:
        The decoded image, converted to RGBA-free greyscale-ready mode.

    Raises:
        ImageRejected: Too large, too many pixels, or not a decodable raster image.
    """
    if not data:
        raise ImageRejected("empty image")
    if len(data) > MAX_IMAGE_BYTES:
        raise ImageRejected(f"image larger than {MAX_IMAGE_BYTES} bytes")
    try:
        with Image.open(io.BytesIO(data)) as probe:
            width, height = probe.size
            if width * height > MAX_IMAGE_PIXELS:
                raise ImageRejected(f"image has {width * height} pixels")
            probe.verify()
        image = Image.open(io.BytesIO(data))
        if getattr(image, "n_frames", 1) > 1:
            image.seek(0)
        image.load()
    except ImageRejected:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError) as e:
        raise ImageRejected(f"not a decodable image: {e}") from e
    return image


def _greyscale(image: Image.Image, size: tuple) -> np.ndarray:
    if image.mode in ("RGBA", "LA", "P"):
        image = image.convert("RGBA")
        background = Image.new("RGBA", image.size, (255, 255, 255, 255))
        image = Image.alpha_composite(background, image)
    return np.asarray(image.convert("L").resize(size, Image.Resampling.LANCZOS), dtype=np.float64)


@lru_cache(maxsize=1)
def _dct_matrix() -> np.ndarray:
    n = np.arange(_DCT_SIZE)
    matrix = np.cos(np.pi * (2 * n[None, :] + 1) * n[:, None] / (2 * _DCT_SIZE))
    matrix[0, :] *= 1 / np.sqrt(2)
    return matrix * np.sqrt(2 / _DCT_SIZE)


def _bits_to_hex(bits: np.ndarray) -> str:
    value = 0
    for bit in bits.flatten():
        value = (value << 1) | int(bool(bit))
    return f"{value:0{_HASH_SIZE * _HASH_SIZE // 4}x}"


def phash(image: Image.Image) -> str:
    """Perceptual hash (DCT).

    Args:
        image: Decoded image.

    Returns:
        16 hex digits.
    """
    pixels = _greyscale(image, (_DCT_SIZE, _DCT_SIZE))
    dct = _dct_matrix()
    coefficients = dct @ pixels @ dct.T
    low = coefficients[:_HASH_SIZE, :_HASH_SIZE]
    return _bits_to_hex(low > np.median(low))


def dhash(image: Image.Image) -> str:
    """Difference hash.

    Args:
        image: Decoded image.

    Returns:
        16 hex digits.
    """
    pixels = _greyscale(image, (_HASH_SIZE + 1, _HASH_SIZE))
    return _bits_to_hex(pixels[:, 1:] > pixels[:, :-1])


def fingerprint(data: bytes) -> Fingerprint:
    """Hash an untrusted image.

    Args:
        data: Image bytes.

    Returns:
        SHA-256, pHash, dHash and size.

    Raises:
        ImageRejected: See :func:`load_image`.
    """
    image = load_image(data)
    return Fingerprint(
        sha256=hashlib.sha256(data).hexdigest(),
        phash=phash(image),
        dhash=dhash(image),
        width=image.size[0],
        height=image.size[1],
    )


def favicon_mmh3(data: bytes) -> int:
    """Shodan-compatible favicon hash.

    Args:
        data: Favicon bytes (any format, hashed as-is).

    Returns:
        Signed 32-bit MurmurHash3 of the MIME base64 encoding.
    """
    return int(mmh3.hash(base64.encodebytes(data)))


def hamming(first: Optional[str], second: Optional[str]) -> Optional[int]:
    """Bits that differ between two hex hashes.

    Args:
        first: Hex hash.
        second: Hex hash of the same length.

    Returns:
        The distance, or ``None`` when either hash is missing or they differ in length.
    """
    if not first or not second or len(first) != len(second):
        return None
    return bin(int(first, 16) ^ int(second, 16)).count("1")
