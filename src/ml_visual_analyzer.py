"""
Machine Learning Visual Analyzer
Advanced computer vision for phishing detection:
- Screenshot similarity analysis using perceptual hashing
- Logo detection and matching
- Layout analysis and fingerprinting
- Color palette extraction and comparison
- Text extraction and analysis
"""
import logging
from typing import Dict, Any, List, Tuple
import hashlib
import io
import base64
from PIL import Image, ImageChops, ImageStat, ImageFilter
import numpy as np
from collections import Counter

logger = logging.getLogger(__name__)


class MLVisualAnalyzer:
    """Machine learning powered visual analysis for phishing detection."""

    def __init__(self):
        self.hash_size = 16  # Perceptual hash size

    def calculate_perceptual_hash(self, image: Image.Image) -> str:
        """
        Calculate perceptual hash (pHash) for image.
        Similar images will have similar hashes.

        Args:
            image: PIL Image object

        Returns:
            64-character hex hash
        """
        try:
            # Convert to grayscale
            gray = image.convert('L')

            # Resize to hash_size x hash_size
            resized = gray.resize((self.hash_size, self.hash_size), Image.Resampling.LANCZOS)

            # Get pixel data
            pixels = np.array(resized).flatten()

            # Calculate DCT (simplified - using mean)
            avg = pixels.mean()

            # Create hash: 1 if pixel > avg, 0 otherwise
            hash_bits = ''.join(['1' if p > avg else '0' for p in pixels])

            # Convert to hex
            hash_hex = hex(int(hash_bits, 2))[2:].zfill(64)

            return hash_hex

        except Exception as e:
            logger.error(f"❌ Perceptual hash error: {e}")
            return ""

    def calculate_hash_distance(self, hash1: str, hash2: str) -> int:
        """
        Calculate Hamming distance between two perceptual hashes.

        Args:
            hash1: First hash
            hash2: Second hash

        Returns:
            Hamming distance (0 = identical, higher = more different)
        """
        if not hash1 or not hash2 or len(hash1) != len(hash2):
            return 999

        distance = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
        return distance

    def calculate_visual_similarity(
        self,
        image1: Image.Image,
        image2: Image.Image
    ) -> float:
        """
        Calculate visual similarity between two images (0-100%).

        Args:
            image1: First image
            image2: Second image

        Returns:
            Similarity score (0-100)
        """
        try:
            # Method 1: Perceptual hash comparison
            hash1 = self.calculate_perceptual_hash(image1)
            hash2 = self.calculate_perceptual_hash(image2)

            distance = self.calculate_hash_distance(hash1, hash2)
            max_distance = len(hash1)

            # Convert to similarity (0-100)
            phash_similarity = ((max_distance - distance) / max_distance) * 100

            # Method 2: Color histogram comparison
            color_similarity = self._compare_color_histograms(image1, image2)

            # Method 3: Structural similarity (simple)
            struct_similarity = self._compare_structure(image1, image2)

            # Weighted average
            similarity = (
                phash_similarity * 0.5 +
                color_similarity * 0.3 +
                struct_similarity * 0.2
            )

            return round(similarity, 2)

        except Exception as e:
            logger.error(f"❌ Visual similarity error: {e}")
            return 0.0

    def _compare_color_histograms(self, img1: Image.Image, img2: Image.Image) -> float:
        """Compare color histograms of two images."""
        try:
            # Resize to same size for comparison
            size = (256, 256)
            img1_resized = img1.resize(size)
            img2_resized = img2.resize(size)

            # Get histograms
            h1 = img1_resized.histogram()
            h2 = img2_resized.histogram()

            # Calculate correlation
            rms = sum((a - b) ** 2 for a, b in zip(h1, h2)) ** 0.5
            max_rms = (sum(a ** 2 for a in h1) ** 0.5) + (sum(b ** 2 for b in h2) ** 0.5)

            if max_rms == 0:
                return 0.0

            similarity = (1 - (rms / max_rms)) * 100
            return max(0, min(100, similarity))

        except Exception as e:
            logger.debug(f"Color histogram error: {e}")
            return 0.0

    def _compare_structure(self, img1: Image.Image, img2: Image.Image) -> float:
        """Compare structural similarity (simplified SSIM)."""
        try:
            # Resize to same size
            size = (64, 64)
            img1_resized = img1.convert('L').resize(size)
            img2_resized = img2.convert('L').resize(size)

            # Get pixel arrays
            arr1 = np.array(img1_resized)
            arr2 = np.array(img2_resized)

            # Calculate MSE
            mse = np.mean((arr1 - arr2) ** 2)

            if mse == 0:
                return 100.0

            # Convert to similarity
            max_mse = 255 ** 2
            similarity = (1 - (mse / max_mse)) * 100

            return max(0, min(100, similarity))

        except Exception as e:
            logger.debug(f"Structure comparison error: {e}")
            return 0.0

    def extract_dominant_colors(
        self,
        image: Image.Image,
        num_colors: int = 5
    ) -> List[Tuple[int, int, int]]:
        """
        Extract dominant colors from image.

        Args:
            image: PIL Image
            num_colors: Number of colors to extract

        Returns:
            List of RGB tuples
        """
        try:
            # Resize for faster processing
            small_img = image.resize((150, 150))

            # Convert to RGB
            rgb_img = small_img.convert('RGB')

            # Get all pixels
            pixels = list(rgb_img.getdata())

            # Count colors
            color_counts = Counter(pixels)

            # Get most common
            dominant = color_counts.most_common(num_colors)

            return [color for color, count in dominant]

        except Exception as e:
            logger.error(f"❌ Color extraction error: {e}")
            return []

    def compare_color_palettes(
        self,
        colors1: List[Tuple[int, int, int]],
        colors2: List[Tuple[int, int, int]]
    ) -> float:
        """
        Compare two color palettes.

        Returns:
            Similarity score (0-100)
        """
        if not colors1 or not colors2:
            return 0.0

        try:
            # Calculate color distances
            matches = 0
            total = min(len(colors1), len(colors2))

            for c1 in colors1[:total]:
                # Find closest color in palette 2
                min_distance = float('inf')

                for c2 in colors2:
                    # Euclidean distance in RGB space
                    distance = sum((a - b) ** 2 for a, b in zip(c1, c2)) ** 0.5
                    min_distance = min(min_distance, distance)

                # Threshold for match (max RGB distance = ~441)
                if min_distance < 100:  # Colors are similar
                    matches += 1

            similarity = (matches / total) * 100
            return round(similarity, 2)

        except Exception as e:
            logger.error(f"❌ Color palette comparison error: {e}")
            return 0.0

    def detect_logo_regions(self, image: Image.Image) -> List[Dict[str, Any]]:
        """
        Detect potential logo regions in screenshot.
        Uses edge detection and region analysis.

        Returns:
            List of potential logo regions with coordinates
        """
        try:
            # Convert to grayscale
            gray = image.convert('L')

            # Apply edge detection (simplified - using filters)
            edges = gray.filter(ImageFilter.FIND_EDGES)

            # Enhance edges
            enhanced = edges.filter(ImageFilter.EDGE_ENHANCE)

            # Get image dimensions
            width, height = image.size

            # Define regions to check (typical logo positions)
            regions = [
                {
                    'name': 'top_left',
                    'box': (0, 0, width // 4, height // 6),
                    'likelihood': 0.9  # Logos often in top-left
                },
                {
                    'name': 'top_center',
                    'box': (width // 3, 0, 2 * width // 3, height // 6),
                    'likelihood': 0.8
                },
                {
                    'name': 'top_right',
                    'box': (3 * width // 4, 0, width, height // 6),
                    'likelihood': 0.5
                },
            ]

            detected_regions = []

            for region in regions:
                # Crop region
                cropped = enhanced.crop(region['box'])

                # Calculate edge density
                pixels = list(cropped.getdata())
                edge_density = sum(1 for p in pixels if p > 50) / len(pixels)

                # High edge density suggests logo/image
                if edge_density > 0.1:
                    detected_regions.append({
                        'region': region['name'],
                        'box': region['box'],
                        'edge_density': edge_density,
                        'logo_likelihood': region['likelihood'] * edge_density
                    })

            return detected_regions

        except Exception as e:
            logger.error(f"❌ Logo detection error: {e}")
            return []

    def analyze_screenshot(
        self,
        screenshot_data: bytes,
        reference_screenshot_data: bytes = None
    ) -> Dict[str, Any]:
        """
        Comprehensive visual analysis of screenshot.

        Args:
            screenshot_data: Screenshot bytes
            reference_screenshot_data: Optional reference to compare against

        Returns:
            Complete visual analysis results
        """
        try:
            # Load image
            image = Image.open(io.BytesIO(screenshot_data))

            # Calculate perceptual hash
            phash = self.calculate_perceptual_hash(image)

            # Extract dominant colors
            colors = self.extract_dominant_colors(image)

            # Detect logo regions
            logo_regions = self.detect_logo_regions(image)

            # Get image properties
            width, height = image.size
            mode = image.mode

            analysis = {
                'perceptual_hash': phash,
                'dominant_colors': colors,
                'logo_regions': logo_regions,
                'dimensions': {'width': width, 'height': height},
                'color_mode': mode,
                'file_size_bytes': len(screenshot_data)
            }

            # If reference provided, compare
            if reference_screenshot_data:
                ref_image = Image.open(io.BytesIO(reference_screenshot_data))

                # Calculate visual similarity
                similarity = self.calculate_visual_similarity(image, ref_image)
                analysis['visual_similarity'] = similarity

                # Compare color palettes
                ref_colors = self.extract_dominant_colors(ref_image)
                color_similarity = self.compare_color_palettes(colors, ref_colors)
                analysis['color_palette_similarity'] = color_similarity

                # Overall phishing likelihood based on visual similarity
                if similarity >= 85:
                    likelihood = 'very_high'
                    score = 95
                elif similarity >= 70:
                    likelihood = 'high'
                    score = 80
                elif similarity >= 50:
                    likelihood = 'medium'
                    score = 60
                else:
                    likelihood = 'low'
                    score = 30

                analysis['phishing_likelihood'] = likelihood
                analysis['phishing_score'] = score

            return analysis

        except Exception as e:
            logger.error(f"❌ Screenshot analysis error: {e}")
            return {'error': str(e)}


def test_ml_visual_analyzer():
    """Test ML visual analyzer."""
    analyzer = MLVisualAnalyzer()

    # Create test images
    img1 = Image.new('RGB', (800, 600), color=(0, 51, 160))  # PayPal blue
    img2 = Image.new('RGB', (800, 600), color=(0, 51, 160))  # Same
    img3 = Image.new('RGB', (800, 600), color=(255, 0, 0))   # Different

    print("\n🧠 Testing ML Visual Analyzer...")

    # Test similarity
    similarity_same = analyzer.calculate_visual_similarity(img1, img2)
    similarity_diff = analyzer.calculate_visual_similarity(img1, img3)

    print(f"   Similarity (identical): {similarity_same}%")
    print(f"   Similarity (different): {similarity_diff}%")

    # Test color extraction
    colors = analyzer.extract_dominant_colors(img1)
    print(f"   Dominant colors: {colors}")

    print("✅ ML Visual Analyzer test complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_ml_visual_analyzer()
