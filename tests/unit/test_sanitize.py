"""Unit tests for core/sanitize.py."""

from core.sanitize import (
    mask_sensitive_patterns,
    normalize_unicode_homoglyphs,
    normalize_whitespace,
    sanitize_for_display,
    sanitize_input,
)


class TestSanitizeInput:
    """Tests for sanitize_input function."""

    def test_strip_whitespace(self):
        """Leading and trailing whitespace is stripped."""
        result = sanitize_input("  hello world  ")
        assert result == "hello world"

    def test_remove_control_chars(self):
        """Control characters are removed."""
        result = sanitize_input("hello\x00world\x1f")
        assert result == "helloworld"

    def test_preserve_newlines_tabs(self):
        """Newlines and tabs are preserved."""
        result = sanitize_input("hello\nworld\there")
        assert result == "hello\nworld\there"

    def test_max_length_truncation(self):
        """Text is truncated to max_length."""
        result = sanitize_input("hello world", max_length=5)
        assert result == "hello"

    def test_disable_control_char_removal(self):
        """Can disable control character removal."""
        result = sanitize_input("hello\x00world", remove_control_chars=False)
        assert result == "hello\x00world"

    def test_disable_homoglyph_normalization(self):
        """Can disable homoglyph normalization."""
        text = "hеllo"  # Cyrillic 'е'
        result = sanitize_input(text, normalize_homoglyphs=False)
        assert result == text

    def test_disable_whitespace_strip(self):
        """Can disable whitespace stripping."""
        result = sanitize_input("  hello  ", strip_whitespace=False)
        assert result == "  hello  "


class TestNormalizeUnicodeHomoglyphs:
    """Tests for normalize_unicode_homoglyphs function."""

    def test_cyrillic_homoglyphs(self):
        """Cyrillic homoglyphs are normalized."""
        # Cyrillic а, е, о
        text = "\u0430\u0435\u043e"
        result = normalize_unicode_homoglyphs(text)
        assert result == "aeo"

    def test_greek_homoglyphs(self):
        """Greek homoglyphs are normalized."""
        # Greek Α, Β, Ε
        text = "\u0391\u0392\u0395"
        result = normalize_unicode_homoglyphs(text)
        assert result == "ABE"

    def test_mixed_text(self):
        """Mixed normal and homoglyph text."""
        # "pаssword" with Cyrillic 'а'
        text = "p\u0430ssword"
        result = normalize_unicode_homoglyphs(text)
        assert result == "password"

    def test_no_homoglyphs(self):
        """Text without homoglyphs is unchanged."""
        text = "normal ascii text"
        result = normalize_unicode_homoglyphs(text)
        assert result == text


class TestSanitizeForDisplay:
    """Tests for sanitize_for_display function."""

    def test_html_escape(self):
        """HTML entities are escaped."""
        result = sanitize_for_display("<script>alert('xss')</script>")
        assert result == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_disable_html_escape(self):
        """Can disable HTML escaping."""
        text = "<b>bold</b>"
        result = sanitize_for_display(text, escape_html=False)
        assert result == text

    def test_truncation(self):
        """Text is truncated with suffix."""
        result = sanitize_for_display("hello world", max_length=8)
        assert result == "hello..."
        assert len(result) == 8

    def test_custom_truncation_suffix(self):
        """Custom truncation suffix."""
        result = sanitize_for_display(
            "hello world", max_length=10, truncation_suffix=" [more]"
        )
        assert result == "hel [more]"

    def test_no_truncation_if_short(self):
        """No truncation if text is shorter than max."""
        result = sanitize_for_display("hi", max_length=10)
        assert result == "hi"


class TestMaskSensitivePatterns:
    """Tests for mask_sensitive_patterns function."""

    def test_mask_api_key(self):
        """API keys are masked."""
        text = 'api_key = "sk-1234567890abcdef"'
        result = mask_sensitive_patterns(text)
        assert "sk-1234567890abcdef" not in result
        assert "********" in result or "*" in result

    def test_mask_bearer_token(self):
        """Bearer tokens are masked."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIs"
        result = mask_sensitive_patterns(text)
        assert "eyJhbGciOiJIUzI1NiIs" not in result

    def test_mask_openai_key(self):
        """OpenAI-style keys are masked."""
        text = "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz"
        result = mask_sensitive_patterns(text)
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in result

    def test_custom_patterns(self):
        """Custom patterns can be provided."""
        text = "secret code: ABC123"
        result = mask_sensitive_patterns(text, patterns=[r"secret code: (\w+)"])
        # Pattern should mask "ABC123"
        assert "ABC123" not in result

    def test_no_sensitive_data(self):
        """Text without sensitive data is unchanged."""
        text = "just normal text here"
        result = mask_sensitive_patterns(text)
        assert result == text


class TestNormalizeWhitespace:
    """Tests for normalize_whitespace function."""

    def test_non_breaking_space(self):
        """Non-breaking spaces are normalized."""
        text = "hello\u00a0world"  # Non-breaking space
        result = normalize_whitespace(text)
        assert result == "hello world"

    def test_various_unicode_spaces(self):
        """Various Unicode spaces are normalized."""
        # Em space, en space, thin space
        text = "a\u2003b\u2002c\u2009d"
        result = normalize_whitespace(text)
        assert result == "a b c d"

    def test_zero_width_space(self):
        """Zero-width spaces are normalized to space then collapsed."""
        text = "hello\u200bworld"  # Zero-width space
        result = normalize_whitespace(text)
        assert result == "hello world"

    def test_collapse_multiple_spaces(self):
        """Multiple spaces are collapsed to one."""
        text = "hello    world"
        result = normalize_whitespace(text)
        assert result == "hello world"

    def test_mixed_whitespace(self):
        """Mixed whitespace types are normalized."""
        text = "a\u00a0\u00a0b  c"
        result = normalize_whitespace(text)
        assert result == "a b c"
