"""
Screenshot Comparison for Visual Phishing Detection
"""
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

try:
    from PIL import Image
    import imagehash
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("PIL/imagehash not available. Screenshot comparison disabled.")


class ScreenshotComparator:
    """Compare screenshots to detect visual similarity between domains."""

    def __init__(self):
        """Initialize screenshot comparator."""
        if not PIL_AVAILABLE:
            logger.error("PIL/imagehash required for screenshot comparison")

    def calculate_image_hash(self, image_path: str) -> Optional[str]:
        """
        Calculate perceptual hash of an image.

        Args:
            image_path: Path to image file

        Returns:
            Image hash as string or None if failed
        """
        if not PIL_AVAILABLE:
            return None

        try:
            img = Image.open(image_path)
            # Use average hash for good balance of speed and accuracy
            ahash = imagehash.average_hash(img)
            return str(ahash)
        except Exception as e:
            logger.error(f"Failed to calculate image hash for {image_path}: {e}")
            return None

    def compare_screenshots(
        self,
        original_path: str,
        suspect_path: str
    ) -> Optional[Dict[str, Any]]:
        """
        Compare two screenshots and calculate visual similarity.

        Args:
            original_path: Path to original (legitimate) domain screenshot
            suspect_path: Path to suspect domain screenshot

        Returns:
            Dict with similarity score (0-100) and is_similar flag
        """
        if not PIL_AVAILABLE:
            return {
                'similarity_score': 0,
                'is_similar': False,
                'error': 'PIL/imagehash not available'
            }

        try:
            # Calculate hashes
            original_hash = self.calculate_image_hash(original_path)
            suspect_hash = self.calculate_image_hash(suspect_path)

            if not original_hash or not suspect_hash:
                return {
                    'similarity_score': 0,
                    'is_similar': False,
                    'error': 'Failed to calculate image hashes'
                }

            # Convert back to imagehash objects for comparison
            orig_hash_obj = imagehash.hex_to_hash(original_hash)
            susp_hash_obj = imagehash.hex_to_hash(suspect_hash)

            # Calculate Hamming distance (lower = more similar)
            distance = orig_hash_obj - susp_hash_obj

            # Convert to similarity score (0-100)
            # Max distance is 64 for 8x8 hash, normalize to 0-100
            max_distance = 64
            similarity_score = max(0, int(100 * (1 - (distance / max_distance))))

            # Consider similar if > 70% match
            is_similar = similarity_score > 70

            result = {
                'similarity_score': similarity_score,
                'is_similar': is_similar,
                'hamming_distance': distance,
                'original_hash': original_hash,
                'suspect_hash': suspect_hash,
                'error': None
            }

            if is_similar:
                logger.warning(
                    f"⚠️  HIGH visual similarity detected! Score: {similarity_score}% "
                    f"(distance: {distance})"
                )

            return result

        except Exception as e:
            logger.error(f"Screenshot comparison failed: {e}")
            return {
                'similarity_score': 0,
                'is_similar': False,
                'error': str(e)
            }

    def batch_compare(
        self,
        original_path: str,
        suspect_paths: list
    ) -> Dict[str, Dict[str, Any]]:
        """
        Compare one original screenshot against multiple suspect screenshots.

        Args:
            original_path: Path to original screenshot
            suspect_paths: List of paths to suspect screenshots

        Returns:
            Dict mapping suspect paths to comparison results
        """
        results = {}

        for suspect_path in suspect_paths:
            result = self.compare_screenshots(original_path, suspect_path)
            results[suspect_path] = result

        return results
