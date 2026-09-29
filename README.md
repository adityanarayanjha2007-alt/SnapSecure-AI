# SnapSecure AI

**Privacy-first, on-device cybersecurity assistant for everyday users**

SnapSecure AI is a desktop cybersecurity prototype designed around local analysis and on-device AI. It helps users understand potentially risky URLs and documents, check password strength locally, and receive simple security guidance.

The project is designed for deployment and validation on qualifying **Snapdragon-powered HP PCs**. Development and initial testing were performed on a non-Snapdragon Windows laptop; therefore, this project does **not** claim Snapdragon performance results until validation is performed on qualifying Snapdragon hardware.

---

## 1. Problem Statement

Everyday users regularly encounter:

- Suspicious links
- Unexpected PDF/DOCX files
- Weak or reused passwords
- Security warnings that are difficult to understand

Many security tools are complex or depend heavily on cloud services. SnapSecure AI aims to provide a simple, privacy-oriented first layer of security analysis directly on the user's device.

---

## 2. Solution

SnapSecure AI combines:

1. **Deterministic security heuristics** for transparent risk analysis
2. **Local password-strength analysis**
3. **Document security indicators**
4. **A local Qwen3.5-0.8B AI component** for future/on-device security explanations and cybersecurity assistance
5. A deployment architecture intended for **Snapdragon-powered HP PCs**

The core risk score is intentionally separated from AI generation. This makes the security indicators easier to inspect and explain.

---

## 3. Core Features

### URL Security Analyzer

Analyzes a URL for indicators such as:

- HTTP instead of HTTPS
- Raw IP addresses
- Security-sensitive keywords
- Suspicious URL patterns
- Unusual URL structure

Example:

```text
http://192.168.1.100/login?verify=password
```

The analyzer can identify the use of HTTP, a raw IP address, and security-sensitive terms.

> The result is a heuristic risk indicator, not proof that a URL is malicious.

### File Security Analyzer

Supports PDF and DOCX files.

The prototype checks for indicators including:

- PDF automatic/open actions
- PDF JavaScript-related actions
- PDF launch-related actions
- Additional active-content indicators
- URLs found in documents
- DOCX macro/VBA indicators
- Basic document metadata

The analyzer does **not** claim to be a full antivirus or malware scanner.

### Password Security Checker

Password analysis is performed locally.

The checker evaluates characteristics such as:

- Length
- Uppercase characters
- Lowercase characters
- Numbers
- Special characters
- Common/simple patterns

Passwords are not intentionally sent to a remote service.

### AI Security Assistant

The project includes **Qwen3.5-0.8B** as a local AI component.

Potential uses include:

- Explaining security findings in simple language
- Answering cybersecurity questions
- Providing guidance after a scan
- Helping non-technical users understand security concepts

The current development build keeps the primary security analysis deterministic and fast. The local Qwen component is intended to be integrated and validated on the target Snapdragon environment.

---

## 4. Architecture

```text
                  ┌─────────────────────────┐
                  │      Streamlit UI       │
                  └────────────┬────────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
       URL Analyzer       File Analyzer    Password Checker
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                     ┌──────────────────┐
                     │   Risk Engine    │
                     │  Heuristic Score │
                     └────────┬─────────┘
                              │
                              ▼
                    Security Explanation
                              │
                              ▼
                  ┌─────────────────────┐
                  │ Local AI Component  │
                  │   Qwen3.5-0.8B      │
                  └─────────────────────┘
                              │
                              ▼
                    User Guidance / FAQ
```

---

## 5. Design Principle

SnapSecure AI deliberately separates:

**Security analysis → AI explanation**

The deterministic layer produces transparent indicators and a heuristic score.

The AI layer can then make the result easier for a user to understand.

This separation reduces the risk of treating a generative AI response as the security verdict itself.

---

## 6. Technology Stack

| Component | Technology |
|---|---|
| Interface | Streamlit |
| Language | Python |
| URL analysis | Python URL parsing + security heuristics |
| Document analysis | pypdf, python-docx |
| Data/utility libraries | pandas, NumPy |
| Local AI | Qwen3.5-0.8B |
| AI framework | PyTorch / Transformers |
| Target platform | Snapdragon-powered HP PC |
| Target AI ecosystem | Qualcomm AI Hub / Snapdragon AI |

---

## 7. Snapdragon Deployment Strategy

The project is intended to be validated on a qualifying Snapdragon-powered HP PC.

The target deployment can use the Snapdragon platform's local AI capabilities to move inference toward the device and reduce dependence on remote AI services.

Qwen3.5-0.8B is a compact model suitable for edge/on-device experimentation and is available through Qualcomm AI Hub.

### Important validation note

The current development machine is an AMD Ryzen-based Windows laptop.

Therefore:

- No Snapdragon benchmark is claimed in this repository.
- No NPU performance number is claimed without measurement.
- Snapdragon deployment/performance should be demonstrated only after testing on qualifying Snapdragon hardware.

---

## 8. Installation

Create and activate a Python virtual environment:

```bash
python -m venv .venv
```

Windows:

```cmd
.venv\Scripts\activate
```

Install the required packages:

```bash
pip install streamlit requests beautifulsoup4 pandas numpy scikit-learn python-dotenv pypdf python-docx transformers torch
```

Run the application:

```bash
streamlit run app.py
```

The Streamlit interface will open in the browser.

---

## 9. Example Workflow

### URL

1. Open **URL Scanner**
2. Enter a URL
3. Select **Analyze URL**
4. Review the risk score
5. Read detected indicators
6. Follow the recommended action

### File

1. Open **File Scanner**
2. Upload a PDF or DOCX
3. Select **Analyze File**
4. Review detected indicators
5. Read the explanation and recommendation

### Password

1. Open **Password Check**
2. Enter a password
3. Select **Check Password**
4. Review the local strength result

### AI Assistant

Open **AI Assistant** to access the project's local AI component and understand how it can be used for security explanations and cybersecurity assistance.

---

## 10. Security and Privacy

SnapSecure AI follows a local-first design.

The project aims to:

- Keep password analysis local
- Minimize unnecessary external data transfer
- Provide transparent security indicators
- Avoid presenting AI output as definitive malware detection
- Give users understandable security recommendations

Users should still avoid uploading confidential documents to any service unless they understand where the data is processed.

---

## 11. Limitations

SnapSecure AI is a cybersecurity assistance prototype and is **not a replacement for professional antivirus, endpoint detection, sandboxing, or malware-analysis systems**.

Important limitations:

- URL scoring is heuristic.
- File indicators do not prove that a document is malicious.
- A low score does not guarantee safety.
- A high score does not prove malicious intent.
- Password strength scoring is not a guarantee against password cracking.
- AI-generated explanations may require verification.
- Snapdragon performance is not claimed until validated on qualifying hardware.

---

## 12. Innovation

The project focuses on making security analysis understandable while keeping the architecture suitable for local/on-device AI.

Key ideas:

### Privacy-first

Security checks can be performed locally instead of requiring every input to be sent to a cloud service.

### Explainable security

The user receives individual indicators instead of only a black-box verdict.

### AI + deterministic security

The risk calculation and AI explanation are separated.

### Edge AI direction

The architecture is designed for deployment on Snapdragon-powered PCs with local AI acceleration.

### Accessibility

The interface is designed for users who may not have formal cybersecurity knowledge.

---

## 13. Future Improvements

Potential next steps include:

- Snapdragon NPU validation and benchmarking
- Qualcomm AI Hub optimized model deployment
- More advanced document inspection
- URL reputation integration
- Browser integration
- Local email/link analysis
- Security education mode
- Offline cybersecurity knowledge base
- More detailed explainable risk scoring
- Additional document formats
- Automated security reports

---

## 14. Project Status

**Prototype / competition submission build**

Implemented:

- URL security analyzer
- PDF/DOCX security analyzer
- Local password checker
- Local Qwen3.5-0.8B AI component
- Security explanations
- Privacy-focused architecture
- Snapdragon deployment target

Pending for a fully validated Snapdragon demonstration:

- Testing on qualifying Snapdragon-powered HP hardware
- Snapdragon-specific performance measurement
- Final NPU/AI Hub deployment validation

---

## 15. Competition Positioning

SnapSecure AI is designed around four evaluation areas:

### Technical Implementation

Python, Streamlit, document parsing, security heuristics, local password analysis, and an on-device AI component form the technical foundation.

### Application Use Case & Innovation

The project addresses a practical problem: helping everyday users understand common cybersecurity risks without requiring advanced technical knowledge.

### Deployment & Accessibility

The lightweight Streamlit interface is easy to run and is designed for a local-first deployment model on Snapdragon-powered PCs.

### Presentation & Documentation

The project provides a clear workflow, transparent limitations, architecture documentation, and a demonstrable security-analysis pipeline.

---

## 16. Responsible Use

SnapSecure AI is intended for defensive cybersecurity education and personal security awareness.

Do not use the tool to access, modify, or analyze systems or files without authorization.

---

## 17. License

This project is a competition prototype. Add the final license and any third-party model/library notices required by the respective licenses before public redistribution.
