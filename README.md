# AI Rules File Scanner

A security tool to detect potentially malicious content hidden in AI assistant rule files (GitHub Copilot, Cursor, etc.)

## About

This application is designed to detect the "Rules File Backdoor" vulnerability reported by Pillar Security in March 2025, as well as Unicode-based obfuscation techniques described by Phylum Security. These vulnerabilities affect AI coding assistants like GitHub Copilot and Cursor, allowing attackers to inject malicious instructions through various Unicode-based deception techniques.

## Features

- Detect invisible Unicode characters that could hide malicious instructions
- Identify Unicode homoglyphs and normalization-based obfuscation techniques
- Detect suspicious patterns and risky keywords in rule files
- Visualize the location of suspicious content in the file
- Parse and analyze rule file structure to identify potentially risky directives
- Generate sanitized and normalized versions of compromised files
- Includes example rule files to demonstrate different obfuscation techniques
- Multiple input methods: file upload or direct content paste

## Running the Application

1. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the Streamlit app:
   ```
   streamlit run app.py
   ```
   
   Or use the provided shell script:
   ```
   ./run.sh
   ```

3. Open your browser and navigate to the URL displayed in the terminal (typically http://localhost:8501)

## How to Use

There are two ways to analyze rule files:

### 1. Upload a File

1. Navigate to the "Upload File" tab
2. Upload a rule file (.cursor, .json, .yaml, etc.) through the file uploader
3. The app will analyze the file and display results

### 2. Paste Content

1. Navigate to the "Paste Content" tab
2. Select the format of your content (JSON, YAML, or Other)
3. Paste your rule file content into the text area
4. Click "Analyze Pasted Content"

### Analysis Results

The app will display:
- Original content with syntax highlighting
- Any invisible characters detected
- Unicode homoglyphs and normalization issues identified
- Suspicious patterns found in the content
- Highlighted view showing potential issues
- Parsed rule structure and analysis
- Options to download sanitized and normalized versions if issues are found

## Security Threats Detected

### 1. Invisible Unicode Characters

Characters like zero-width spaces and joiners that are invisible to human reviewers but can contain instructions that manipulate AI behavior.

### 2. Unicode Homoglyphs and Normalization

Mathematical, bold, or italic Unicode variants that look similar to ASCII characters but can bypass traditional security tools:
- For example, variables like `𝘀𝗲𝗹𝒇` (visually similar to "self")
- According to Phylum Security research, a word like "self" can have over 122,000 Unicode variants

### 3. Malicious Rule Directives

Instructions that appear legitimate but guide the AI to insert harmful code.

### 4. Supply Chain Risks

Compromised rule files can spread through project templates, open-source contributions, and developer communities.

## References

- [Pillar Security Blog: New Vulnerability in GitHub Copilot and Cursor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [Phylum Research: Malicious Actors Use Unicode Support in Python to Evade Detection](https://blog.phylum.io/malicious-actors-use-unicode-support-in-python-to-evade-detection)
- [Unicode Security Considerations](https://www.unicode.org/reports/tr36/)
- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/)
- [PEP-672: Unicode-related Security Considerations for Python](https://peps.python.org/pep-0672/) 