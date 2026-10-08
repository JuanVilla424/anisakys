"""SerpApi multi-engine image search with dynamic expansion."""

import boto3
import serpapi
from typing import List
from urllib.parse import urlparse, parse_qs

from src.logger import logger


class ImageSearchClient:
    def __init__(self, api_key: str, s3_bucket: str, aws_region: str):
        self.api_key = api_key
        self.s3_bucket = s3_bucket
        self.s3 = boto3.client("s3", region_name=aws_region)
        self._client = serpapi.Client(api_key=api_key)

    def _generate_presigned_url(self, s3_key: str, expiration: int = 3600) -> str:
        url = self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.s3_bucket, "Key": s3_key},
            ExpiresIn=expiration,
        )
        return url

    def search_by_s3_key(self, s3_key: str) -> List[dict]:
        image_url = self._generate_presigned_url(s3_key)
        return self.search_by_url(image_url)

    def _follow_serpapi_link(self, serpapi_url: str) -> dict:
        parsed = urlparse(serpapi_url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params["api_key"] = self.api_key
        return dict(self._client.search(params))

    def search_by_url(self, image_url: str) -> List[dict]:
        try:
            seen_urls = set()
            all_results = []

            def _add(url, title, thumbnail, source):
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    all_results.append(
                        {
                            "url": url,
                            "title": title,
                            "thumbnail": thumbnail,
                            "source": source,
                        }
                    )

            # 1. Google Lens visual_matches
            data = dict(
                self._client.search(
                    {
                        "engine": "google_lens",
                        "url": image_url,
                        "type": "visual_matches",
                    }
                )
            )

            if "error" in data:
                logger.error(f"google_lens visual_matches error: {data['error']}")
                raise Exception(data["error"])

            visual_matches = data.get("visual_matches", [])
            exact_links = []

            for match in visual_matches:
                _add(
                    match.get("link"),
                    match.get("title"),
                    match.get("thumbnail"),
                    match.get("source"),
                )
                if match.get("serpapi_exact_matches_link"):
                    exact_links.append(match["serpapi_exact_matches_link"])

            logger.info(
                f"Google Lens visual_matches: {len(visual_matches)} hits, "
                f"{len(exact_links)} exact_match links to follow"
            )
            visual_count = len(all_results)

            # 2. Follow serpapi_exact_matches_link from each visual match
            for link in exact_links:
                try:
                    edata = self._follow_serpapi_link(link)
                    for match in edata.get("exact_matches", []):
                        _add(
                            match.get("link"),
                            match.get("title"),
                            match.get("thumbnail"),
                            match.get("source"),
                        )
                except Exception as e:
                    logger.error(f"exact_match link failed: {e}")

            exact_count = len(all_results) - visual_count
            logger.info(
                f"Exact matches expansion: {exact_count} new URLs from {len(exact_links)} links"
            )

            # 3. Follow related_content serpapi_links
            related_content = data.get("related_content", [])
            related_links = [r["serpapi_link"] for r in related_content if r.get("serpapi_link")]

            for link in related_links:
                try:
                    rdata = self._follow_serpapi_link(link)
                    for result in rdata.get("organic_results", []):
                        _add(
                            result.get("link"),
                            result.get("title"),
                            None,
                            result.get("displayed_link"),
                        )
                except Exception as e:
                    logger.error(f"related_content link failed: {e}")

            related_count = len(all_results) - visual_count - exact_count
            logger.info(
                f"Related content expansion: {related_count} new URLs from {len(related_links)} links"
            )

            # 4. Yandex Reverse Image
            try:
                ydata = dict(
                    self._client.search(
                        {
                            "engine": "yandex_images",
                            "url": image_url,
                        }
                    )
                )
                if "error" not in ydata:
                    for match in ydata.get("image_results", []):
                        _add(
                            match.get("source_url"),
                            match.get("title"),
                            match.get("thumbnail"),
                            match.get("source"),
                        )
            except Exception as e:
                logger.error(f"yandex failed: {e}")

            yandex_count = len(all_results) - visual_count - exact_count - related_count

            # 5. Google Reverse Image (max_results for broader coverage)
            try:
                ridata = dict(
                    self._client.search(
                        {
                            "engine": "google_reverse_image",
                            "image_url": image_url,
                            "max_results": "200",
                        }
                    )
                )
                if "error" not in ridata:
                    for match in ridata.get("image_results", []):
                        _add(
                            match.get("link"),
                            match.get("title"),
                            match.get("thumbnail"),
                            match.get("source"),
                        )
            except Exception as e:
                logger.error(f"google_reverse_image failed: {e}")

            reverse_count = (
                len(all_results) - visual_count - exact_count - related_count - yandex_count
            )

            logger.info(
                f"Total: {len(all_results)} unique URLs "
                f"(visual={visual_count}, exact_expansion={exact_count}, "
                f"related={related_count}, yandex={yandex_count}, reverse_image={reverse_count})"
            )
            return all_results
        except Exception as e:
            logger.error(f"Image search failed: {e}")
            raise
