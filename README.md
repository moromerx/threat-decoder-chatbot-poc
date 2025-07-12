# Threat Decoder Chatbot

Threat Decoder Chatbot is an intelligent streamlit-based AI assistant designed for Security Operations Center (SOC) tasks. It helps you decode various encodings (Base64, Base32, URL) and fetch threat intelligence from VirusTotal using file hashes or IP addresses.

---

## 🚀 Setup

### Prerequisites
- Python 3.8 or higher
- OpenAI API key
- VirusTotal API key

### Installation

Clone the repository:
```bash
git clone https://github.com/moromerx/threat-decoder-chatbot-poc.git
cd threat-decoder-chatbot-poc
```

Create a virtual environment:
```bash
python -m venv .venv
# On Unix/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### Environment Variables

Copy the example environment file and add your API keys:
```bash
cp .env.example .env
# Edit .env with your OpenAI and VirusTotal API keys
```

- `OPENAI_API_KEY` - Your OpenAI API key
- `VIRUSTOTAL_API_KEY` - Your VirusTotal API key
- `OPENAI_BASE_URL` (optional) - Custom OpenAI endpoint if not using the default

---

## ▶️ Run

Start the chatbot UI:
```bash
streamlit run main.py
```

---

## 💬 Example Interactions

```
User: Decode this Base64 string: SGVsbG8gd29ybGQh
🤖 Assistant: The decoded string is: Hello world!

User: Get VirusTotal info for hash cb1553a3c88817e4cc774a5a93f9158f6785bd3815447d04b6c3f4c2c4b21ed7
🤖 Assistant: [Fetches and displays threat intelligence for the hash]

User: Decode this URL: https%3A%2F%2Fexample.com%2Fmalware
🤖 Assistant: The decoded URL is: https://example.com/malware

User: Get VirusTotal info for IP 8.8.8.8
🤖 Assistant: [Fetches and displays threat intelligence for the IP]
```
