"""
Input and output sanitization utilities.

Provides functions for sanitizing user input before processing and
sanitizing output for safe display to users.
"""

import html
import re

# Common control characters that may be used in injection attempts
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# Unicode homoglyphs and confusables that may be used to evade detection
HOMOGLYPH_MAP = {
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0443': 'y',  # Cyrillic у
    '\u0445': 'x',  # Cyrillic х
    '\u0391': 'A',  # Greek Α
    '\u0392': 'B',  # Greek Β
    '\u0395': 'E',  # Greek Ε
    '\u0397': 'H',  # Greek Η
    '\u0399': 'I',  # Greek Ι
    '\u039a': 'K',  # Greek Κ
    '\u039c': 'M',  # Greek Μ
    '\u039d': 'N',  # Greek Ν
    '\u039f': 'O',  # Greek Ο
    '\u03a1': 'P',  # Greek Ρ
    '\u03a4': 'T',  # Greek Τ
    '\u03a7': 'X',  # Greek Χ
    '\u03a5': 'Y',  # Greek Υ
    '\u0417': 'Z',  # Greek Ζ
}


def sanitize_input(
    text: str,
    remove_control_chars: bool = True,
    normalize_homoglyphs: bool = True,
    max_length: int | None = None,
    strip_whitespace: bool = True,
) -> str:
    """Sanitize input text for safe processing.

    Applies various sanitization steps to prepare text for detection.
    This does NOT modify the text for security purposes - the detectors
    will still see potentially malicious content. This normalizes the
    text to improve detection accuracy.

    Args:
        text: Raw input text to sanitize.
        remove_control_chars: Remove ASCII control characters.
        normalize_homoglyphs: Replace Unicode homoglyphs with ASCII equivalents.
        max_length: Truncate text to this length (None = no limit).
        strip_whitespace: Strip leading/trailing whitespace.

    Returns:
        Sanitized text.
    """
    if strip_whitespace:
        text = text.strip()

    if remove_control_chars:
        text = CONTROL_CHARS.sub('', text)

    if normalize_homoglyphs:
        text = normalize_unicode_homoglyphs(text)

    if max_length is not None and len(text) > max_length:
        text = text[:max_length]

    return text


def normalize_unicode_homoglyphs(text: str) -> str:
    """Replace Unicode homoglyphs with their ASCII equivalents.

    This helps detect injection attempts that use visually similar
    characters to evade keyword-based detection.

    Args:
        text: Text potentially containing homoglyphs.

    Returns:
        Text with homoglyphs replaced by ASCII equivalents.
    """
    result = []
    for char in text:
        result.append(HOMOGLYPH_MAP.get(char, char))
    return ''.join(result)


def sanitize_for_display(
    text: str,
    escape_html: bool = True,
    max_length: int | None = None,
    truncation_suffix: str = "...",
) -> str:
    """Sanitize text for safe display in user interfaces.

    Used when showing potentially malicious input back to users,
    such as in detection reports or logs.

    Args:
        text: Text to sanitize for display.
        escape_html: Escape HTML entities to prevent XSS.
        max_length: Maximum length before truncation.
        truncation_suffix: Suffix to add when truncating.

    Returns:
        Text safe for display.
    """
    if escape_html:
        text = html.escape(text)

    if max_length is not None and len(text) > max_length:
        # Account for suffix length
        truncate_at = max_length - len(truncation_suffix)
        if truncate_at > 0:
            text = text[:truncate_at] + truncation_suffix
        else:
            text = text[:max_length]

    return text


def mask_sensitive_patterns(
    text: str,
    patterns: list[str] | None = None,
    mask_char: str = '*',
) -> str:
    """Mask sensitive patterns in text for logging.

    Args:
        text: Text potentially containing sensitive data.
        patterns: Regex patterns to mask. Defaults to common secrets.
        mask_char: Character to use for masking.

    Returns:
        Text with sensitive patterns masked.
    """
    if patterns is None:
        patterns = [
            r'(?i)(api[_-]?key|api[_-]?secret|password|passwd|secret)["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
            r'(?i)(bearer|token)\s+([A-Za-z0-9_\-\.]+)',
            r'sk-[A-Za-z0-9]{20,}',  # OpenAI-style keys
            r'(?i)anthropic[_-]?key["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
        ]

    result = text
    for pattern in patterns:
        def mask_match(match: re.Match) -> str:
            full_match = match.group(0)
            # Keep the prefix, mask the sensitive part
            if match.lastindex and match.lastindex >= 2:
                prefix = match.group(1)
                sensitive = match.group(2)
                return f"{prefix}: {mask_char * min(len(sensitive), 8)}"
            return mask_char * min(len(full_match), 16)

        result = re.sub(pattern, mask_match, result)

    return result


def normalize_whitespace(text: str) -> str:
    """Normalize various whitespace characters to standard spaces.

    Helps detect injection attempts that use unusual whitespace
    characters to evade detection.

    Args:
        text: Text with potentially unusual whitespace.

    Returns:
        Text with normalized whitespace.
    """
    # Various Unicode whitespace characters
    whitespace_chars = [
        '\u00a0',  # Non-breaking space
        '\u2000',  # En quad
        '\u2001',  # Em quad
        '\u2002',  # En space
        '\u2003',  # Em space
        '\u2004',  # Three-per-em space
        '\u2005',  # Four-per-em space
        '\u2006',  # Six-per-em space
        '\u2007',  # Figure space
        '\u2008',  # Punctuation space
        '\u2009',  # Thin space
        '\u200a',  # Hair space
        '\u200b',  # Zero-width space
        '\u202f',  # Narrow no-break space
        '\u205f',  # Medium mathematical space
        '\u3000',  # Ideographic space
        '\ufeff',  # Zero-width no-break space (BOM)
    ]

    for ws in whitespace_chars:
        text = text.replace(ws, ' ')

    # Collapse multiple spaces into one
    text = re.sub(r' +', ' ', text)

    return text
