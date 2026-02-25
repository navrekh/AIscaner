"""
AIScan Advanced Detection Module
- Code detection (.py .js .java .ts .cpp etc)
- Rewrite/humanizer detection (Quillbot, Undetectable.ai patterns)
- Multilingual detection (Hindi, Spanish, French, Arabic)
- Image metadata analysis (AI-generated image detection)
"""
import re, math, json, logging
from pathlib import Path
from collections import Counter
from dataclasses import dataclass

log = logging.getLogger("aiscan")


# ════════════════════════════════════════════════════════════════════════════
# 1. CODE DETECTION
# ════════════════════════════════════════════════════════════════════════════

CODE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs",
                   ".go", ".rs", ".swift", ".kt", ".php", ".rb", ".r"}

# AI code patterns — overly clean, over-commented, perfect structure
AI_CODE_PHRASES = [
    "# this function", "# this method", "# this class",
    "# initialize", "# define", "# create a",
    "# step 1", "# step 2", "# step 3",
    "# example usage", "# main function",
    "here's", "here is", "certainly", "of course",
    "# note:", "# todo:", "# fixme:",
]

AI_CODE_PATTERNS = [
    r'"""[\s\S]{20,200}"""',          # Docstrings on everything
    r'#\s+[A-Z][a-z].*\n.*\n.*\n',   # Comment every 3 lines
    r'def \w+\([^)]*\):\s*\n\s+"""', # Every function has docstring
]


def detect_code(text: str, extension: str) -> dict:
    """Detect AI-generated code."""
    lines = text.split('\n')
    n_lines = max(1, len(lines))

    # Comment ratio (AI over-comments)
    comment_lines = sum(1 for l in lines if l.strip().startswith(('#', '//', '/*', '*', '"""', "'''")))
    comment_ratio = comment_lines / n_lines

    # Empty lines ratio (AI adds lots of spacing)
    empty_lines = sum(1 for l in lines if not l.strip())
    empty_ratio = empty_lines / n_lines

    # Docstring density
    docstrings = len(re.findall(r'"""[\s\S]*?"""', text))
    functions  = len(re.findall(r'\bdef \w+|function \w+|\bclass \w+', text))
    doc_ratio  = docstrings / max(1, functions)

    # AI phrase detection in comments
    text_lower = text.lower()
    phrase_hits = sum(1 for p in AI_CODE_PHRASES if p in text_lower)

    # Pattern matching
    pattern_hits = sum(1 for p in AI_CODE_PATTERNS if re.search(p, text))

    # Perfect naming (AI uses very descriptive camelCase/snake_case)
    long_names = len(re.findall(r'\b[a-z]+_[a-z]+_[a-z]+\b|\b[a-z][a-z]+[A-Z][a-z]+[A-Z][a-z]+\b', text))

    # Score
    score = 0.0
    reasons = []

    if comment_ratio > 0.35:
        score += 25
        reasons.append(f"Excessive commenting ({comment_ratio:.0%} of lines)")
    if doc_ratio > 0.7:
        score += 20
        reasons.append("Docstring on every function (AI pattern)")
    if phrase_hits > 2:
        score += min(30, phrase_hits * 8)
        reasons.append(f"AI phrases in comments ({phrase_hits} found)")
    if pattern_hits > 1:
        score += 15
    if empty_ratio > 0.4:
        score += 10
        reasons.append("Excessive blank lines (AI formatting)")

    score = min(100, score)
    risk = "High" if score >= 70 else "Medium" if score >= 40 else "Low"

    return {
        "score": round(score, 1),
        "risk": risk,
        "reasons": reasons,
        "comment_ratio": round(comment_ratio, 2),
        "doc_ratio": round(doc_ratio, 2),
        "type": "code"
    }


# ════════════════════════════════════════════════════════════════════════════
# 2. REWRITE / HUMANIZER DETECTION
# Detects text that was AI-generated then "humanized" with tools like
# Quillbot, Undetectable.ai, GPTMinus1 etc.
# ════════════════════════════════════════════════════════════════════════════

# Humanized text signatures:
# - Unusual word substitutions (utilise → employ, however → yet)
# - Inconsistent formality (mixes formal and casual suddenly)
# - Awkward phrasing from synonym replacement
# - Perplexity spikes (some sentences very complex, others very simple)

HUMANIZER_SUBSTITUTIONS = [
    ("furthermore", ["additionally", "also", "plus", "what's more"]),
    ("utilize", ["employ", "make use of", "leverage", "harness"]),
    ("however", ["yet", "still", "even so", "that said", "be that as it may"]),
    ("demonstrate", ["show", "reveal", "illustrate", "make clear"]),
    ("significant", ["notable", "considerable", "marked", "pronounced"]),
    ("implement", ["put into practice", "carry out", "execute", "enact"]),
]

AWKWARD_PATTERNS = [
    r'\b(notwithstanding|heretofore|aforementioned|hereinafter)\b',  # overly formal
    r'\b(gonna|wanna|kinda|sorta|yeah)\b',   # suddenly casual
    r'\w{15,}',                              # suspiciously long words
    r'[,;]{2,}',                             # double punctuation
]


def detect_rewrite(text: str) -> dict:
    """Detect AI text that has been run through a humanizer tool."""
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if len(s.split()) >= 3]
    words = text.lower().split()
    n = max(1, len(words))
    n_sent = max(1, len(sentences))
    text_lower = text.lower()

    score = 0.0
    reasons = []

    # 1. Perplexity variance — humanizers create uneven complexity
    if len(sentences) >= 4:
        sent_lengths = [len(s.split()) for s in sentences]
        mean_sl = sum(sent_lengths) / len(sent_lengths)
        # Coefficient of variation
        std_sl = math.sqrt(sum((l-mean_sl)**2 for l in sent_lengths) / len(sent_lengths))
        cv = std_sl / mean_sl if mean_sl > 0 else 0

        # Humanized: high variance in sentence complexity
        # Natural AI: low variance
        # Natural Human: medium variance
        if cv > 0.7:
            score += 20
            reasons.append("Uneven sentence complexity (humanizer pattern)")

    # 2. Formality inconsistency
    formal_count   = len(re.findall(r'\b(notwithstanding|aforementioned|heretofore|pursuant)\b', text_lower))
    informal_count = len(re.findall(r"\b(gonna|wanna|kinda|yeah|nope|yep|ok|okay)\b", text_lower))
    if formal_count > 0 and informal_count > 0:
        score += 30
        reasons.append("Mixed formal/informal register (humanizer signature)")

    # 3. Awkward synonym substitutions
    awkward_hits = sum(1 for p in AWKWARD_PATTERNS if re.search(p, text_lower))
    if awkward_hits >= 2:
        score += 15
        reasons.append("Unusual word choices (possible synonym replacement)")

    # 4. Unusual punctuation patterns from rewriting
    em_dashes = text.count('—')
    if em_dashes > n_sent * 0.3:
        score += 10
        reasons.append("Excessive em-dashes (AI rewrite pattern)")

    # 5. Vocabulary that's too varied (humanizers use thesaurus aggressively)
    freq = Counter(words)
    hapax = sum(1 for w in freq if freq[w] == 1 and len(w) > 5)
    hapax_ratio = hapax / n
    if hapax_ratio > 0.6:
        score += 15
        reasons.append("Unusually high vocabulary diversity (thesaurus overuse)")

    score = min(100, score)
    risk = "High" if score >= 60 else "Medium" if score >= 35 else "Low"

    return {
        "score": round(score, 1),
        "risk": risk,
        "reasons": reasons,
        "type": "rewrite"
    }


# ════════════════════════════════════════════════════════════════════════════
# 3. MULTILINGUAL DETECTION
# Hindi, Spanish, French, Arabic AI signatures
# ════════════════════════════════════════════════════════════════════════════

MULTILINGUAL_AI_PHRASES = {
    "hi": [  # Hindi
        "इसके अलावा", "इसके अतिरिक्त", "यह महत्वपूर्ण है",
        "विभिन्न पहलुओं", "इस संदर्भ में", "निष्कर्ष के रूप में",
        "उल्लेखनीय है", "विशेष रूप से", "इस प्रकार",
        "सुनिश्चित करना", "प्रभावी ढंग से",
    ],
    "es": [  # Spanish
        "además", "asimismo", "cabe destacar", "en este sentido",
        "es importante señalar", "en conclusión", "por lo tanto",
        "sin embargo", "no obstante", "en definitiva",
        "implementar", "optimizar", "facilitar",
    ],
    "fr": [  # French
        "par ailleurs", "en outre", "il est important de noter",
        "en conclusion", "ainsi", "néanmoins", "cependant",
        "toutefois", "il convient de", "dans ce contexte",
        "optimiser", "faciliter", "mettre en œuvre",
    ],
    "ar": [  # Arabic
        "علاوة على ذلك", "من المهم أن", "في الختام",
        "وبالتالي", "ومع ذلك", "في هذا السياق",
        "تجدر الإشارة", "من الجدير بالذكر",
    ]
}

def detect_language(text: str) -> str:
    """Simple language detection based on character sets and common words."""
    # Hindi - Devanagari script
    if len(re.findall(r'[\u0900-\u097F]', text)) > 10:
        return "hi"
    # Arabic script
    if len(re.findall(r'[\u0600-\u06FF]', text)) > 10:
        return "ar"
    # French indicators
    french_chars = len(re.findall(r'[éèêëàâùûîïôç]', text.lower()))
    if french_chars > 5:
        return "fr"
    # Spanish indicators
    spanish_chars = len(re.findall(r'[áéíóúüñ¿¡]', text.lower()))
    if spanish_chars > 5:
        return "es"
    return "en"


def detect_multilingual(text: str) -> dict:
    """Detect AI patterns in non-English text."""
    lang = detect_language(text)

    if lang == "en":
        return {"score": 0, "language": "en", "reasons": [], "type": "multilingual"}

    phrases = MULTILINGUAL_AI_PHRASES.get(lang, [])
    hits = sum(1 for p in phrases if p in text)

    score = min(100, hits * 15)
    reasons = []
    if hits > 0:
        matched = [p for p in phrases if p in text][:3]
        reasons.append(f"AI phrases in {lang.upper()}: {', '.join(matched)}")

    lang_names = {"hi": "Hindi", "es": "Spanish", "fr": "French", "ar": "Arabic"}

    return {
        "score": round(score, 1),
        "risk": "High" if score >= 60 else "Medium" if score >= 30 else "Low",
        "language": lang,
        "language_name": lang_names.get(lang, lang),
        "reasons": reasons,
        "type": "multilingual"
    }


# ════════════════════════════════════════════════════════════════════════════
# 4. IMAGE METADATA ANALYSIS
# Detect AI-generated images embedded in documents
# ════════════════════════════════════════════════════════════════════════════

AI_IMAGE_GENERATORS = [
    "stable diffusion", "midjourney", "dall-e", "dall·e",
    "firefly", "imagen", "kandinsky", "bing image creator",
    "dreamstudio", "nightcafe", "leonardo.ai", "runway",
    "generative", "ai generated", "generated by",
]

AI_IMAGE_SOFTWARE = [
    "Adobe Firefly", "Stable Diffusion", "Midjourney",
    "DALL-E", "ComfyUI", "Automatic1111", "InvokeAI",
]


def analyze_image_metadata(image_path: Path) -> dict:
    """
    Analyze image metadata for AI generation signatures.
    Checks EXIF data, XMP metadata, file structure.
    """
    result = {
        "is_ai_generated": False,
        "confidence": "Low",
        "signals": [],
        "generator": None,
        "score": 0
    }

    try:
        # Method 1: Check file bytes for AI signatures
        raw = image_path.read_bytes()
        raw_str = raw[:8192].decode('latin-1', errors='ignore').lower()

        for gen in AI_IMAGE_GENERATORS:
            if gen.lower() in raw_str:
                result["is_ai_generated"] = True
                result["generator"] = gen
                result["signals"].append(f"Generator signature found: {gen}")
                result["score"] = 95
                result["confidence"] = "High"
                return result

        # Method 2: PIL/Pillow metadata
        try:
            from PIL import Image
            img = Image.open(image_path)
            info = img.info or {}

            # Check PNG metadata
            for key, val in info.items():
                val_str = str(val).lower()
                for gen in AI_IMAGE_GENERATORS:
                    if gen.lower() in val_str:
                        result["is_ai_generated"] = True
                        result["generator"] = gen
                        result["signals"].append(f"PNG metadata: {gen}")
                        result["score"] = 90
                        result["confidence"] = "High"
                        return result

            # Check for "parameters" key (Stable Diffusion)
            if "parameters" in info:
                result["is_ai_generated"] = True
                result["signals"].append("Stable Diffusion parameters found in metadata")
                result["score"] = 95
                result["confidence"] = "High"
                result["generator"] = "Stable Diffusion"
                return result

            # Check EXIF
            exif = img._getexif() if hasattr(img, '_getexif') else None
            if exif:
                exif_str = str(exif).lower()
                for gen in AI_IMAGE_GENERATORS:
                    if gen in exif_str:
                        result["is_ai_generated"] = True
                        result["generator"] = gen
                        result["signals"].append(f"EXIF data: {gen}")
                        result["score"] = 85
                        result["confidence"] = "High"

            # Check dimensions (AI images often have specific sizes)
            w, h = img.size
            ai_sizes = [(512,512),(768,768),(1024,1024),(512,768),(768,512),
                       (1024,576),(576,1024),(896,1152),(1152,896)]
            if (w, h) in ai_sizes:
                result["signals"].append(f"AI-typical dimensions: {w}×{h}")
                result["score"] = max(result["score"], 30)

        except Exception: pass

    except Exception as e:
        log.debug(f"Image analysis error: {e}")

    result["confidence"] = "High" if result["score"] > 80 else "Medium" if result["score"] > 40 else "Low"
    return result


def extract_images_from_docx(docx_path: Path, output_dir: Path) -> list:
    """Extract embedded images from a Word document."""
    import zipfile
    images = []
    output_dir.mkdir(exist_ok=True)

    try:
        with zipfile.ZipFile(docx_path) as z:
            for name in z.namelist():
                if name.startswith('word/media/'):
                    ext = Path(name).suffix.lower()
                    if ext in ('.png', '.jpg', '.jpeg', '.gif', '.webp'):
                        out_path = output_dir / Path(name).name
                        out_path.write_bytes(z.read(name))
                        images.append(out_path)
    except Exception as e:
        log.debug(f"Image extraction error: {e}")

    return images


def scan_document_images(doc_path: Path, temp_dir: Path) -> dict:
    """Scan all images embedded in a document."""
    ext = doc_path.suffix.lower()
    images = []

    if ext == '.docx':
        images = extract_images_from_docx(doc_path, temp_dir / "images")
    elif ext in ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'):
        images = [doc_path]

    if not images:
        return {"has_images": False, "ai_images": 0, "total_images": 0, "results": []}

    results = []
    ai_count = 0
    for img in images:
        r = analyze_image_metadata(img)
        if r["is_ai_generated"]:
            ai_count += 1
        results.append({
            "file": img.name,
            "is_ai": r["is_ai_generated"],
            "score": r["score"],
            "generator": r["generator"],
            "signals": r["signals"]
        })

    return {
        "has_images": len(images) > 0,
        "total_images": len(images),
        "ai_images": ai_count,
        "results": results,
        "score": (ai_count / len(images) * 100) if images else 0
    }
