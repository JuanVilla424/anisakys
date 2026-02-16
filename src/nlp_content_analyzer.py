"""
NLP Content Analyzer
Natural Language Processing for phishing detection:
- Text extraction from HTML
- Keyword and phrase analysis
- Urgency/scam language detection
- Brand mention analysis
- Semantic similarity measurement
- Suspicious pattern detection
"""
import re
import logging
from typing import Dict, Any, List, Set
from bs4 import BeautifulSoup
from collections import Counter
import difflib

logger = logging.getLogger(__name__)


class NLPContentAnalyzer:
    """NLP-powered content analysis for phishing detection."""

    def __init__(self):
        # Phishing keywords (urgency, threats, incentives)
        self.urgency_keywords = [
            'urgent', 'immediately', 'now', 'today', 'expire', 'expires',
            'limited time', 'act now', 'hurry', 'quick', 'asap', 'suspended',
            'locked', 'freeze', 'frozen', 'restricted', 'unusual activity',
            'verify immediately', 'confirm now', 'update required'
        ]

        self.threat_keywords = [
            'suspend', 'suspended', 'block', 'blocked', 'close', 'closed',
            'terminate', 'terminated', 'remove', 'removed', 'delete', 'deleted',
            'compromise', 'compromised', 'unauthorized', 'unusual', 'suspicious',
            'fraud', 'fraudulent', 'illegal', 'violation', 'breach'
        ]

        self.incentive_keywords = [
            'prize', 'winner', 'won', 'free', 'bonus', 'reward', 'refund',
            'cash', 'money', 'million', 'thousand', 'dollars', 'claim',
            'congratulations', 'selected', 'chosen', 'lucky'
        ]

        self.credential_keywords = [
            'password', 'username', 'login', 'sign in', 'account',
            'verify', 'confirm', 'update', 'validate', 'ssn',
            'social security', 'credit card', 'bank', 'pin',
            'cvv', 'security code', 'personal information'
        ]

        # Common legitimate company domains
        self.legitimate_indicators = [
            'privacy policy', 'terms of service', 'unsubscribe',
            'contact us', 'customer service', 'help center',
            'about us', 'careers', 'copyright'
        ]

    def extract_text_from_html(self, html: str) -> Dict[str, Any]:
        """
        Extract and analyze text content from HTML.

        Args:
            html: HTML content

        Returns:
            Extracted text and metadata
        """
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Remove script and style elements
            for script in soup(['script', 'style', 'noscript']):
                script.decompose()

            # Get text
            text = soup.get_text(separator=' ', strip=True)

            # Get title
            title = soup.title.string if soup.title else ""

            # Get meta description
            meta_desc = ""
            meta_tag = soup.find('meta', attrs={'name': 'description'})
            if meta_tag and meta_tag.get('content'):
                meta_desc = meta_tag['content']

            # Get all links
            links = [a.get('href', '') for a in soup.find_all('a', href=True)]

            # Get forms
            forms = soup.find_all('form')
            form_actions = [form.get('action', '') for form in forms]
            form_fields = []

            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    field_type = inp.get('type', 'text')
                    field_name = inp.get('name', '')
                    form_fields.append({
                        'type': field_type,
                        'name': field_name
                    })

            return {
                'text': text,
                'title': title,
                'meta_description': meta_desc,
                'links': links,
                'link_count': len(links),
                'forms': {
                    'count': len(forms),
                    'actions': form_actions,
                    'fields': form_fields
                },
                'text_length': len(text),
                'word_count': len(text.split())
            }

        except Exception as e:
            logger.error(f"❌ HTML text extraction error: {e}")
            return {'text': '', 'error': str(e)}

    def analyze_phishing_indicators(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for phishing indicators using NLP.

        Args:
            text: Text content to analyze

        Returns:
            Phishing indicator analysis
        """
        text_lower = text.lower()

        # Count keyword occurrences
        urgency_count = sum(1 for kw in self.urgency_keywords if kw in text_lower)
        threat_count = sum(1 for kw in self.threat_keywords if kw in text_lower)
        incentive_count = sum(1 for kw in self.incentive_keywords if kw in text_lower)
        credential_count = sum(1 for kw in self.credential_keywords if kw in text_lower)
        legitimate_count = sum(1 for kw in self.legitimate_indicators if kw in text_lower)

        # Find specific matches
        urgency_matches = [kw for kw in self.urgency_keywords if kw in text_lower]
        threat_matches = [kw for kw in self.threat_keywords if kw in text_lower]
        incentive_matches = [kw for kw in self.incentive_keywords if kw in text_lower]
        credential_matches = [kw for kw in self.credential_keywords if kw in text_lower]

        # Calculate suspicion score
        score = 0

        # High urgency is suspicious
        if urgency_count >= 3:
            score += 25
        elif urgency_count >= 2:
            score += 15
        elif urgency_count >= 1:
            score += 5

        # Threats are very suspicious
        if threat_count >= 3:
            score += 30
        elif threat_count >= 2:
            score += 20
        elif threat_count >= 1:
            score += 10

        # Incentives can indicate scams
        if incentive_count >= 3:
            score += 20
        elif incentive_count >= 2:
            score += 10

        # Credential requests are suspicious
        if credential_count >= 3:
            score += 25
        elif credential_count >= 2:
            score += 15
        elif credential_count >= 1:
            score += 5

        # Lack of legitimate indicators is suspicious
        if legitimate_count == 0:
            score += 15
        elif legitimate_count <= 2:
            score += 5

        # Excessive capitalization (SHOUTING)
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3:
            score += 15
        elif caps_ratio > 0.2:
            score += 10

        # Excessive exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count >= 5:
            score += 10
        elif exclamation_count >= 3:
            score += 5

        score = min(score, 100)

        return {
            'suspicion_score': score,
            'urgency_count': urgency_count,
            'threat_count': threat_count,
            'incentive_count': incentive_count,
            'credential_count': credential_count,
            'legitimate_count': legitimate_count,
            'urgency_matches': urgency_matches[:10],
            'threat_matches': threat_matches[:10],
            'incentive_matches': incentive_matches[:10],
            'credential_matches': credential_matches[:10],
            'caps_ratio': round(caps_ratio, 3),
            'exclamation_count': exclamation_count
        }

    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate semantic similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity score (0-100)
        """
        try:
            # Use SequenceMatcher for text similarity
            similarity = difflib.SequenceMatcher(None, text1.lower(), text2.lower()).ratio()
            return round(similarity * 100, 2)

        except Exception as e:
            logger.error(f"❌ Text similarity error: {e}")
            return 0.0

    def extract_brand_mentions(self, text: str, brands: List[str]) -> Dict[str, int]:
        """
        Extract and count brand mentions in text.

        Args:
            text: Text to analyze
            brands: List of brand names to search for

        Returns:
            Dict of brand -> mention count
        """
        text_lower = text.lower()
        mentions = {}

        for brand in brands:
            brand_lower = brand.lower()
            count = text_lower.count(brand_lower)

            if count > 0:
                mentions[brand] = count

        return mentions

    def analyze_form_fields(self, form_fields: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Analyze form fields for suspicious patterns.

        Args:
            form_fields: List of form field dicts

        Returns:
            Form analysis results
        """
        suspicious_score = 0
        suspicious_fields = []

        password_count = 0
        email_count = 0
        credit_card_count = 0
        ssn_count = 0

        for field in form_fields:
            field_type = field.get('type', '').lower()
            field_name = field.get('name', '').lower()

            # Check for sensitive fields
            if field_type == 'password' or 'password' in field_name:
                password_count += 1
                suspicious_fields.append(field_name or 'password')

            if 'email' in field_name:
                email_count += 1

            if 'card' in field_name or 'cvv' in field_name or 'ccv' in field_name:
                credit_card_count += 1
                suspicious_fields.append(field_name)
                suspicious_score += 20

            if 'ssn' in field_name or 'social' in field_name:
                ssn_count += 1
                suspicious_fields.append(field_name)
                suspicious_score += 30

            if 'pin' in field_name and field_type == 'password':
                suspicious_fields.append(field_name)
                suspicious_score += 25

        # Multiple password fields is very suspicious
        if password_count >= 2:
            suspicious_score += 25
        elif password_count == 1:
            suspicious_score += 10

        # Credit card request without SSN is common phishing
        if credit_card_count > 0:
            suspicious_score += 20

        return {
            'suspicious_score': min(suspicious_score, 100),
            'password_fields': password_count,
            'email_fields': email_count,
            'credit_card_fields': credit_card_count,
            'ssn_fields': ssn_count,
            'suspicious_field_names': suspicious_fields
        }

    def comprehensive_content_analysis(
        self,
        html: str,
        reference_text: str = None,
        target_brands: List[str] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive NLP analysis on HTML content.

        Args:
            html: HTML content
            reference_text: Optional reference text to compare against
            target_brands: Optional list of brands to check for

        Returns:
            Complete content analysis
        """
        try:
            # Extract text and metadata
            extraction = self.extract_text_from_html(html)

            if extraction.get('error'):
                return extraction

            text = extraction['text']
            forms = extraction['forms']

            # Analyze phishing indicators
            phishing_analysis = self.analyze_phishing_indicators(text)

            # Analyze forms
            form_analysis = self.analyze_form_fields(forms['fields'])

            # Calculate combined suspicion score
            combined_score = int(
                phishing_analysis['suspicion_score'] * 0.6 +
                form_analysis['suspicious_score'] * 0.4
            )

            analysis = {
                'text_extraction': extraction,
                'phishing_indicators': phishing_analysis,
                'form_analysis': form_analysis,
                'combined_suspicion_score': combined_score
            }

            # If reference text provided, compare
            if reference_text:
                similarity = self.calculate_text_similarity(text, reference_text)
                analysis['text_similarity'] = similarity

            # If brands provided, search for mentions
            if target_brands:
                brand_mentions = self.extract_brand_mentions(text, target_brands)
                analysis['brand_mentions'] = brand_mentions

            # Determine threat level
            if combined_score >= 75:
                analysis['threat_level'] = 'critical'
            elif combined_score >= 60:
                analysis['threat_level'] = 'high'
            elif combined_score >= 40:
                analysis['threat_level'] = 'medium'
            else:
                analysis['threat_level'] = 'low'

            return analysis

        except Exception as e:
            logger.error(f"❌ Comprehensive content analysis error: {e}")
            return {'error': str(e)}


def test_nlp_analyzer():
    """Test NLP content analyzer."""
    analyzer = NLPContentAnalyzer()

    # Test phishing text
    phishing_text = """
    URGENT: Your PayPal account has been SUSPENDED due to unusual activity!
    You must verify your account IMMEDIATELY or it will be permanently closed.
    Click here to confirm your password and credit card information NOW!
    Act within 24 hours or lose access forever!
    """

    print("\n📝 Testing NLP Content Analyzer...")

    analysis = analyzer.analyze_phishing_indicators(phishing_text)

    print(f"   Suspicion Score: {analysis['suspicion_score']}/100")
    print(f"   Urgency keywords: {analysis['urgency_count']}")
    print(f"   Threat keywords: {analysis['threat_count']}")
    print(f"   Matches: {analysis['urgency_matches'][:3]}")

    print("✅ NLP analyzer test complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_nlp_analyzer()
