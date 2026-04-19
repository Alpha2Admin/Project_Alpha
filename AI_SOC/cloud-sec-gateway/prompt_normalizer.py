"""
AI-CASB v5.0 — Prompt Normalizer
=================================
Pre-processes user prompts to neutralize adversarial evasion techniques
BEFORE they reach the DLP/DeBERTa inspection engine.

Pipeline:
  1. Unicode canonicalization (NFKC + confusable mapping)
  2. Encoding detection & decoding (base64, hex, ROT13, URL-encoding)
  3. Whitespace normalization (zero-width chars, invisible separators)
  4. Leetspeak reversal
  5. Language detection (flags non-English for extra scrutiny)

RAM Impact: ~2 MB
"""

import re
import base64
import unicodedata
import urllib.parse
from typing import Tuple

# ── Confusable Character Map (Cyrillic / Greek → Latin) ──────────────────────
# Maps visually similar characters from other scripts to ASCII equivalents.
CONFUSABLE_MAP = {
    # Cyrillic
    '\u0410': 'A', '\u0430': 'a',  # А/а
    '\u0412': 'B', '\u0432': 'b',  # В/в (looks like B/b)
    '\u0421': 'C', '\u0441': 'c',  # С/с
    '\u0415': 'E', '\u0435': 'e',  # Е/е
    '\u041D': 'H', '\u043D': 'h',  # Н/н
    '\u041A': 'K', '\u043A': 'k',  # К/к
    '\u041C': 'M', '\u043C': 'm',  # М/м
    '\u041E': 'O', '\u043E': 'o',  # О/о
    '\u0420': 'P', '\u0440': 'p',  # Р/р
    '\u0422': 'T', '\u0442': 't',  # Т/т
    '\u0425': 'X', '\u0445': 'x',  # Х/х
    '\u0423': 'Y', '\u0443': 'y',  # У/у
    '\u0456': 'i',                  # і (Ukrainian i)
    '\u0406': 'I',                  # І (Ukrainian I)
    # Greek
    '\u0391': 'A', '\u03B1': 'a',  # Α/α
    '\u0392': 'B', '\u03B2': 'b',  # Β/β
    '\u0395': 'E', '\u03B5': 'e',  # Ε/ε
    '\u0397': 'H', '\u03B7': 'h',  # Η/η
    '\u0399': 'I', '\u03B9': 'i',  # Ι/ι
    '\u039A': 'K', '\u03BA': 'k',  # Κ/κ
    '\u039C': 'M', '\u03BC': 'm',  # Μ/μ
    '\u039D': 'N', '\u03BD': 'n',  # Ν/ν
    '\u039F': 'O', '\u03BF': 'o',  # Ο/ο
    '\u03A1': 'P', '\u03C1': 'p',  # Ρ/ρ
    '\u03A4': 'T', '\u03C4': 't',  # Τ/τ
    '\u03A7': 'X', '\u03C7': 'x',  # Χ/χ
    '\u03A5': 'Y', '\u03C5': 'y',  # Υ/υ
    '\u0396': 'Z', '\u03B6': 'z',  # Ζ/ζ
    # Fullwidth Latin
    '\uFF21': 'A', '\uFF22': 'B', '\uFF23': 'C', '\uFF24': 'D', '\uFF25': 'E',
    '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
}

# ── Leetspeak Map ────────────────────────────────────────────────────────────
LEET_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
}

# ── Zero-Width / Invisible Characters ────────────────────────────────────────
INVISIBLE_CHARS = re.compile(
    '[\u200b\u200c\u200d\u200e\u200f'     # Zero-width space/joiner/non-joiner
    '\u2060\u2061\u2062\u2063\u2064'       # Word joiner, invisible operators
    '\ufeff'                                # BOM
    '\u00ad'                                # Soft hyphen
    '\u034f'                                # Combining grapheme joiner
    '\u061c'                                # Arabic letter mark
    '\u115f\u1160'                          # Hangul fillers
    '\u17b4\u17b5'                          # Khmer inherent vowels
    '\u180e'                                # Mongolian vowel separator
    ']'
)

# ── Base64 Detection Pattern ────────────────────────────────────────────────
BASE64_PATTERN = re.compile(
    r'(?:^|[\s:="\'])([A-Za-z0-9+/]{20,}={0,2})(?:[\s"\']|$)'
)

# ── Hex-Encoded String Pattern ──────────────────────────────────────────────
HEX_PATTERN = re.compile(
    r'(?:0x|\\x)?([0-9a-fA-F]{2}(?:[:\s]?[0-9a-fA-F]{2}){7,})'
)


def _apply_confusable_map(text: str) -> str:
    """Replace visually confusable characters with ASCII equivalents."""
    return ''.join(CONFUSABLE_MAP.get(c, c) for c in text)


def _normalize_unicode(text: str) -> str:
    """Apply NFKC normalization + confusable character mapping."""
    # NFKC: decomposes then recomposes using compatibility mappings
    # Converts fullwidth, accented, ligatures to their canonical forms
    normalized = unicodedata.normalize('NFKC', text)
    # Then apply our confusable map for Cyrillic/Greek lookalikes
    return _apply_confusable_map(normalized)


def _remove_invisible_chars(text: str) -> str:
    """Strip zero-width spaces, joiners, and other invisible Unicode."""
    return INVISIBLE_CHARS.sub('', text)


def _decode_base64_segments(text: str) -> str:
    """Find and decode base64-encoded segments inline."""
    def _try_decode(match):
        b64_str = match.group(1)
        try:
            decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            # Only replace if the decoded text looks like readable text
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return f" {decoded} "
        except Exception:
            pass
        return match.group(0)

    return BASE64_PATTERN.sub(_try_decode, text)


def _decode_hex_segments(text: str) -> str:
    """Find and decode hex-encoded segments inline."""
    def _try_decode(match):
        hex_str = match.group(1).replace(':', '').replace(' ', '').replace('\\x', '')
        try:
            decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
            if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                return f" {decoded} "
        except Exception:
            pass
        return match.group(0)

    return HEX_PATTERN.sub(_try_decode, text)


def _decode_url_encoding(text: str) -> str:
    """Decode URL-encoded characters (%20, %3C, etc.)."""
    try:
        decoded = urllib.parse.unquote(text)
        return decoded
    except Exception:
        return text


def _apply_rot13(text: str) -> str:
    """Check if text might be ROT13 and decode. Only applied if keywords emerge."""
    import codecs
    try:
        decoded = codecs.decode(text, 'rot_13')
        # Check if common injection keywords appear in decoded version
        injection_keywords = ['ignore', 'system', 'prompt', 'instructions', 'reveal',
                              'password', 'secret', 'admin', 'override', 'bypass']
        for kw in injection_keywords:
            if kw in decoded.lower() and kw not in text.lower():
                return decoded
    except Exception:
        pass
    return text


def _reverse_leetspeak(text: str) -> str:
    """Convert leetspeak to regular text for detection purposes."""
    # Only apply to words that look like they might be leetspeak
    # (mix of letters and leet characters like "1gn0r3")
    words = text.split()
    result = []
    for word in words:
        has_leet = any(c in LEET_MAP for c in word)
        has_alpha = any(c.isalpha() for c in word)
        if has_leet and has_alpha and len(word) > 3:
            converted = ''.join(LEET_MAP.get(c, c) for c in word)
            result.append(converted)
        else:
            result.append(word)
    return ' '.join(result)


def _detect_language(text: str) -> str:
    """
    Lightweight language detection based on Unicode script analysis.
    Returns the dominant script: 'latin', 'cyrillic', 'arabic', 'cjk',
    'devanagari', or 'mixed'.
    No external dependencies — uses Unicode character categories.
    """
    script_counts = {'latin': 0, 'cyrillic': 0, 'arabic': 0, 'cjk': 0, 'devanagari': 0, 'other': 0}

    for char in text:
        cp = ord(char)
        if 0x0041 <= cp <= 0x024F:     # Basic Latin + Extensions
            script_counts['latin'] += 1
        elif 0x0400 <= cp <= 0x04FF:   # Cyrillic
            script_counts['cyrillic'] += 1
        elif 0x0600 <= cp <= 0x06FF:   # Arabic
            script_counts['arabic'] += 1
        elif 0x4E00 <= cp <= 0x9FFF or 0x3040 <= cp <= 0x30FF:  # CJK + Kana
            script_counts['cjk'] += 1
        elif 0x0900 <= cp <= 0x097F:   # Devanagari
            script_counts['devanagari'] += 1

    total = sum(script_counts.values())
    if total == 0:
        return 'latin'

    dominant = max(script_counts, key=script_counts.get)
    dominant_ratio = script_counts[dominant] / total

    # If no single script dominates (< 70%), it's mixed
    if dominant_ratio < 0.7:
        return 'mixed'
    return dominant


from deep_translator import GoogleTranslator

def normalize_prompt(text: str) -> Tuple[str, dict]:
    """
    Main normalization pipeline. Returns (normalized_text, metadata).

    The metadata dict contains:
      - original_length: int
      - normalized_length: int
      - edit_distance_ratio: float (0.0 = no change, 1.0 = completely different)
      - language: str
      - evasion_detected: bool
      - evasion_techniques: list[str]
    """
    if not text or len(text) < 3:
        return text, {"evasion_detected": False, "evasion_techniques": [], "language": "latin"}

    original = text
    evasion_techniques = []

    # Step 1: Remove invisible characters
    cleaned = _remove_invisible_chars(text)
    if len(cleaned) != len(text):
        evasion_techniques.append("invisible_chars")
    text = cleaned

    # Step 2: Unicode normalization (NFKC + confusables)
    text = _normalize_unicode(text)
    if text != cleaned:
        evasion_techniques.append("unicode_confusables")

    # Step 3: URL decoding
    decoded = _decode_url_encoding(text)
    if decoded != text:
        evasion_techniques.append("url_encoding")
    text = decoded

    # Step 4: Base64 decoding
    decoded = _decode_base64_segments(text)
    if decoded != text:
        evasion_techniques.append("base64_encoding")
    text = decoded

    # Step 5: Hex decoding
    decoded = _decode_hex_segments(text)
    if decoded != text:
        evasion_techniques.append("hex_encoding")
    text = decoded

    # Step 6: ROT13 check
    decoded = _apply_rot13(text)
    if decoded != text:
        evasion_techniques.append("rot13")
    text = decoded

    # Step 7: Leetspeak reversal
    decoded = _reverse_leetspeak(text)
    if decoded != text:
        evasion_techniques.append("leetspeak")
    text = decoded

    # Step 8: Language detection & Translation
    language = _detect_language(text)
    if language not in ('latin', 'other'):
        evasion_techniques.append(f"non_latin_script:{language}")
        try:
            translated = GoogleTranslator(source='auto', target='en').translate(text)
            if translated and translated.strip() != "":
                text = translated
        except Exception as e:
            print(f"Translation error: {e}")

    # Calculate edit distance ratio (simple character-level diff)
    orig_lower = original.lower().replace(' ', '')
    norm_lower = text.lower().replace(' ', '')
    if len(orig_lower) > 0:
        # Simple ratio: how many characters changed
        common = sum(1 for a, b in zip(orig_lower, norm_lower) if a == b)
        max_len = max(len(orig_lower), len(norm_lower))
        edit_ratio = 1.0 - (common / max_len) if max_len > 0 else 0.0
    else:
        edit_ratio = 0.0

    evasion_detected = len(evasion_techniques) > 0

    metadata = {
        "original_length": len(original),
        "normalized_length": len(text),
        "edit_distance_ratio": round(edit_ratio, 4),
        "language": language,
        "evasion_detected": evasion_detected,
        "evasion_techniques": evasion_techniques,
    }

    return text, metadata
