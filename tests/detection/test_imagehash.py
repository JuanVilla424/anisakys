"""Image fingerprints (src/detection/imagehash.py): stable, robust, and safe on hostile input."""

import io
import random

import mmh3
import pytest
from PIL import Image, ImageDraw

from src.detection import imagehash
from src.detection.imagehash import (
    ImageRejected,
    dhash,
    favicon_mmh3,
    fingerprint,
    hamming,
    load_image,
    phash,
)


def _logo(size=(128, 128), color=(200, 30, 30), fmt="PNG") -> bytes:
    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)
    w, h = size
    draw.ellipse((w * 0.1, h * 0.1, w * 0.9, h * 0.9), fill=color)
    draw.rectangle((w * 0.35, h * 0.2, w * 0.65, h * 0.8), fill="white")
    buffer = io.BytesIO()
    image.save(buffer, fmt)
    return buffer.getvalue()


class TestHashes:
    def test_resized_and_recompressed_copies_stay_close(self):
        # A textured picture: a perfectly symmetric flat drawing leaves most DCT
        # coefficients at zero and is a known blind spot of pHash, real logos are not.
        rng = random.Random(7)
        picture = Image.new("RGB", (256, 256), "white")
        draw = ImageDraw.Draw(picture)
        for _ in range(40):
            x, y = rng.randrange(0, 220), rng.randrange(0, 220)
            draw.rectangle(
                (x, y, x + rng.randrange(10, 60), y + rng.randrange(10, 60)),
                fill=tuple(rng.randrange(256) for _ in range(3)),
            )
        buffer = io.BytesIO()
        picture.save(buffer, "PNG")
        data = buffer.getvalue()
        copy = io.BytesIO()
        Image.open(io.BytesIO(data)).resize((64, 64)).save(copy, "JPEG", quality=70)

        original = fingerprint(data)
        smaller = fingerprint(copy.getvalue())

        assert len(original.phash) == 16 and len(original.dhash) == 16
        assert (hamming(original.phash, smaller.phash) or 0) <= 10
        assert (hamming(original.dhash, smaller.dhash) or 0) <= 12

    def test_different_pictures_are_far(self):
        logo = load_image(_logo())
        stripes = Image.new("L", (128, 128))
        stripes.putdata([(x // 8 % 2) * 255 for y in range(128) for x in range(128)])

        assert (hamming(phash(logo), phash(stripes)) or 0) > 20
        assert (hamming(dhash(logo), dhash(stripes)) or 0) > 20

    def test_transparent_images_are_flattened_on_white(self):
        rgba = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        ImageDraw.Draw(rgba).ellipse((8, 8, 56, 56), fill=(0, 0, 255, 255))
        buffer = io.BytesIO()
        rgba.save(buffer, "PNG")

        print_ = fingerprint(buffer.getvalue())

        assert print_.width == 64 and print_.height == 64 and print_.sha256

    def test_hamming_needs_two_hashes_of_the_same_length(self):
        assert hamming("ff", "00") == 8
        assert hamming(None, "00") is None
        assert hamming("fff", "00") is None


class TestFaviconHash:
    def test_matches_the_shodan_formula(self):
        # mmh3 of the MIME base64 text, newline included (what Shodan/Censys index).
        assert favicon_mmh3(b"hello") == mmh3.hash(b"aGVsbG8=\n")


class TestHostileInput:
    def test_empty_and_garbage_bytes_are_rejected(self):
        with pytest.raises(ImageRejected):
            load_image(b"")
        with pytest.raises(ImageRejected):
            load_image(b"<html>not an image</html>")

    def test_oversized_files_are_rejected(self, monkeypatch):
        monkeypatch.setattr(imagehash, "MAX_IMAGE_BYTES", 100)

        with pytest.raises(ImageRejected, match="larger than"):
            load_image(_logo())

    def test_pixel_bombs_are_rejected_before_decoding(self, monkeypatch):
        monkeypatch.setattr(imagehash, "MAX_IMAGE_PIXELS", 100)

        with pytest.raises(ImageRejected, match="pixels"):
            load_image(_logo((20, 20)))

    def test_animated_images_use_the_first_frame(self):
        frames = [Image.new("RGB", (32, 32), c) for c in ("red", "blue")]
        buffer = io.BytesIO()
        frames[0].save(buffer, "GIF", save_all=True, append_images=frames[1:])

        assert fingerprint(buffer.getvalue()).width == 32
