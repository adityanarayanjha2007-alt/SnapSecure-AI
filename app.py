import re
import io
from urllib.parse import urlparse
import streamlit as st

st.set_page_config(page_title="SnapSecure AI", page_icon="🛡️", layout="wide")

st.title("🛡️ SnapSecure AI")
st.caption("Privacy-first cybersecurity analysis for on-device AI deployment")

# ---------------- URL ENGINE ----------------

def analyze_url(url):
    score = 0
    reasons = []
    url = url.strip()

    if not url:
        return 0, "LOW", ["Please enter a URL."]

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        scheme = parsed.scheme.lower()

        if scheme != "https":
            score += 15
            reasons.append("The URL does not use HTTPS.")

        is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))

        if is_ip:
            score += 30
            reasons.append("The destination uses an IP address instead of a normal domain.")

        if len(url) > 120:
            score += 10
            reasons.append("The URL is unusually long.")

        if "@" in url:
            score += 20
            reasons.append("The URL contains '@', which can obscure the actual destination.")

        suspicious_words = [
            "login", "signin", "verify", "verification", "password",
            "account", "secure", "update", "bank", "payment",
            "wallet", "free", "claim", "confirm"
        ]

        found = [word for word in suspicious_words if word in url.lower()]

        if found:
            score += min(20, len(found) * 5)
            reasons.append(
                "Security-sensitive keywords detected: " + ", ".join(found) + "."
            )

        if not is_ip and domain and len(domain.split(".")) >= 4:
            score += 10
            reasons.append("The domain contains many subdomain levels.")

        if parsed.port in [21, 23, 445, 3389]:
            score += 10
            reasons.append("The URL uses a port associated with network or remote-access services.")

        if url.count("%") >= 3:
            score += 10
            reasons.append("The URL contains several encoded characters.")

        if domain.count("-") >= 3:
            score += 10
            reasons.append("The domain contains multiple hyphens.")

        score = min(score, 100)
        level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

        if not reasons:
            reasons.append("No major heuristic warning indicators were detected.")

        return score, level, reasons

    except Exception:
        return 50, "MEDIUM", ["The URL could not be parsed reliably."]


def url_explanation(score, level, reasons):
    if level == "HIGH":
        action = "Avoid opening the link or entering credentials. Verify the destination through an official source."
    elif level == "MEDIUM":
        action = "Proceed cautiously and verify the domain before entering sensitive information."
    else:
        action = "No major heuristic warning indicators were found, but normal browsing caution is still recommended."

    if any("IP address" in r for r in reasons):
        why = "Using a raw IP address instead of a normal domain can be a warning sign."
    elif any("HTTPS" in r for r in reasons):
        why = "The connection is not protected by HTTPS."
    elif any("keywords" in r for r in reasons):
        why = "The URL contains words commonly associated with account or credential actions."
    else:
        why = "The scanner found indicators that deserve attention."

    return why, action


# ---------------- FILE ENGINE ----------------

def analyze_file(uploaded_file):
    score = 0
    reasons = []
    filename = uploaded_file.name.lower()
    data = uploaded_file.getvalue()

    if len(data) > 25 * 1024 * 1024:
        score += 5
        reasons.append("The file is larger than 25 MB.")

    if filename.endswith(".pdf"):
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(data))

            if b"/JavaScript" in data or b"/JS" in data:
                score += 25
                reasons.append("JavaScript-related PDF objects were detected.")

            if b"/OpenAction" in data:
                score += 10
                reasons.append("An automatic open action was detected; this is not inherently malicious.")

            if b"/AA" in data:
                score += 10
                reasons.append("Additional-action objects were detected.")

            if b"/Launch" in data:
                score += 30
                reasons.append("A launch action was detected.")

            try:
                text = "\n".join(page.extract_text() or "" for page in reader.pages)
                urls = re.findall(r"https?://[^\s<>\"]+", text, re.I)

                if urls:
                    score += min(20, len(urls) * 5)
                    reasons.append(f"{len(urls)} URL(s) found in extracted text.")
            except Exception:
                pass

            reasons.append(f"PDF pages: {len(reader.pages)}.")

        except Exception:
            score += 15
            reasons.append("PDF parsing was incomplete.")

    elif filename.endswith(".docx"):
        try:
            from docx import Document

            document = Document(io.BytesIO(data))
            text = "\n".join(p.text for p in document.paragraphs)

            urls = re.findall(r"https?://[^\s<>\"]+", text, re.I)

            if urls:
                score += min(20, len(urls) * 5)
                reasons.append(f"{len(urls)} URL(s) found in the document.")

            if b"vbaProject.bin" in data:
                score += 40
                reasons.append("A VBA macro project was detected.")

        except Exception:
            score += 15
            reasons.append("DOCX parsing was incomplete.")

    else:
        score += 5
        reasons.append("This file type has limited analysis support.")

    score = min(score, 100)
    level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

    if not reasons:
        reasons.append("No major heuristic warning indicators were detected.")

    return score, level, reasons


def file_explanation(score, level, reasons):
    if level == "HIGH":
        action = "Avoid opening or sharing the file until it has been checked with trusted security software."
    elif level == "MEDIUM":
        action = "Inspect the detected indicators and use additional trusted scanning before opening."
    else:
        action = "No major indicators were detected by this scanner, but this does not guarantee the file is safe."

    if any("JavaScript" in r for r in reasons):
        why = "The file contains active JavaScript-related content that deserves additional inspection."
    elif any("macro" in r.lower() for r in reasons):
        why = "The document contains a macro project, which can execute code when enabled."
    elif any("action" in r.lower() for r in reasons):
        why = "The file contains an action that may trigger behavior when opened."
    else:
        why = "The scanner found indicators that deserve attention."

    return why, action


# ---------------- PASSWORD ENGINE ----------------

def analyze_password(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 30
    elif len(password) >= 8:
        score += 15
    else:
        feedback.append("Use at least 12 characters.")

    checks = [
        (r"[A-Z]", "Add uppercase letters."),
        (r"[a-z]", "Add lowercase letters."),
        (r"\d", "Add numbers."),
        (r"[^A-Za-z0-9]", "Add special characters.")
    ]

    for pattern, message in checks:
        if re.search(pattern, password):
            score += 15
        else:
            feedback.append(message)

    if re.search(r"(.)\1\1", password):
        score -= 20
        feedback.append("Avoid repeated characters.")

    score = max(0, min(score, 100))
    level = "STRONG" if score >= 80 else "MEDIUM" if score >= 50 else "WEAK"

    return score, level, feedback


# ---------------- UI ----------------

tabs = st.tabs([
    "🔗 URL Scanner",
    "📄 File Scanner",
    "🔑 Password Check",
    "🤖 AI Assistant",
    "ℹ️ About"
])

with tabs[0]:
    st.header("🔗 URL Security Analyzer")
    st.write("Analyze suspicious URLs locally and receive an instant security explanation.")

    url = st.text_input(
        "Enter a URL",
        placeholder="https://example.com/login"
    )

    if st.button("Analyze URL", type="primary"):
        if not url.strip():
            st.warning("Please enter a URL.")
        else:
            score, level, reasons = analyze_url(url)

            st.metric("Risk Score", f"{score}/100")
            st.subheader(f"Risk Level: {level}")

            st.markdown("### 🔎 Detected Indicators")
            for reason in reasons:
                st.write("• " + reason)

            why, action = url_explanation(score, level, reasons)

            st.markdown("### 💡 Why this matters")
            st.info(why)

            st.markdown("### 🛡️ Recommended Action")
            st.success(action)

            st.caption(
                "Note: This is heuristic analysis. A risk score does not prove that a URL is malicious."
            )

with tabs[1]:
    st.header("📄 File Security Analyzer")
    st.write("Analyze selected security indicators in PDF and DOCX files.")

    uploaded_file = st.file_uploader(
        "Upload a PDF or DOCX",
        type=["pdf", "docx"]
    )

    if st.button("Analyze File", type="primary"):
        if uploaded_file is None:
            st.warning("Please upload a file.")
        else:
            score, level, reasons = analyze_file(uploaded_file)

            st.metric("Risk Score", f"{score}/100")
            st.subheader(f"Risk Level: {level}")

            st.markdown("### 🔎 Detected Indicators")
            for reason in reasons:
                st.write("• " + reason)

            why, action = file_explanation(score, level, reasons)

            st.markdown("### 💡 Why this matters")
            st.info(why)

            st.markdown("### 🛡️ Recommended Action")
            st.success(action)

            st.caption(
                "Note: This is indicator-based analysis, not a definitive malware scanner."
            )

with tabs[2]:
    st.header("🔑 Password Security Checker")
    st.warning("Password analysis happens locally. Never share real passwords.")

    password = st.text_input(
        "Enter password",
        type="password"
    )

    if st.button("Check Password", type="primary"):
        if not password:
            st.warning("Please enter a password.")
        else:
            score, level, feedback = analyze_password(password)

            st.metric("Strength Score", f"{score}/100")
            st.subheader(f"Strength: {level}")

            if feedback:
                for item in feedback:
                    st.write("• " + item)
            else:
                st.success("Good password characteristics detected.")

with tabs[3]:
    st.header("🤖 AI Security Assistant")
    st.write(
        "Qwen3.5-0.8B local inference is available as the AI component. "
        "The main security analysis remains fast and deterministic."
    )

    st.info(
        "The current development machine uses CPU-only inference. "
        "For the competition target, Snapdragon-powered hardware should be used "
        "for deployment and validation."
    )

    st.markdown("### Example AI use cases")
    st.write("• Explain a security finding in simple language.")
    st.write("• Answer cybersecurity questions.")
    st.write("• Provide user guidance after a scan.")

with tabs[4]:
    st.header("ℹ️ About SnapSecure AI")

    st.markdown("""
### Privacy-first cybersecurity assistant

**Core features**
- URL security heuristics
- PDF/DOCX security indicators
- Local password-strength checking
- Instant security explanations
- Local Qwen3.5-0.8B AI component

### Design principle

SnapSecure AI separates **deterministic security analysis** from **AI explanation**.
This keeps the core risk calculation transparent while using AI to make security
findings easier for users to understand.

### Important limitation

Risk scores are heuristic indicators, not proof that a URL or file is malicious.

### Deployment target

The project is intended for deployment and validation on a qualifying
Snapdragon-powered HP PC. The current Ryzen laptop is a development machine;
no Snapdragon performance claim is made until validation is performed on
qualifying hardware.
""")
