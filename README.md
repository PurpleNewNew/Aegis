# AJS: AI-Powered JavaScript Reverse Engineering Assistant

WARNING！！！LOTS OF VIBE CODING！！

**AJS** is a specialized tool designed to assist security researchers and developers in understanding and reverse-engineering complex, obfuscated front-end JavaScript, with a primary focus on cryptographic functions.

It leverages the Chrome DevTools Protocol (CDP) and Large Language Models (LLMs) to turn the tedious process of manual debugging and code analysis into a fast, AI-driven query.

## How it Works

The tool's architecture is simple and powerful:

1.  **Live Debugging**: AJS connects to your running Chrome browser instance. Its `CDPDebugger` component sets dynamic breakpoints on key user interaction events (`click`, `submit`, `change`).

2.  **Contextual Snippet Extraction**: When you perform an action on a web page (e.g., clicking a "Login" button that triggers encryption), the debugger catches the event. Instead of dumping the entire script, it intelligently extracts a small, relevant snippet of the JavaScript code around the breakpoint, along with the values of local variables at that exact moment.

3.  **AI-Powered Analysis**: This high-value "intelligence packet" (code snippet + variables) is sent to an LLM. The LLM is given a specific persona: a **JavaScript Reverse Engineering Expert**. It is tasked with:
    *   Identifying the encryption algorithm (AES, RSA, etc.).
    *   Locating cryptographic keys, IVs, and other constants in the code or variables.
    *   Providing a step-by-step explanation of the encryption logic.

4.  **Instant Results**: The AI's analysis is printed directly to your console, giving you immediate insight into how the front-end encryption works.

This process transforms a potentially hours-long RE task into a simple action-and-response loop.

## Installation and Usage

### Prerequisites
- Python 3.10+
- A running instance of Google Chrome or a Chromium-based browser.
- Access to an OpenAI-compatible LLM API (e.g., a local LM Studio, Ollama, or the official OpenAI API).

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch Chrome with Remote Debugging
For AJS to connect, you must start Chrome with a remote debugging port enabled. First, close all existing Chrome instances. Then, run the appropriate command for your OS:

**Windows**
```bash
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222
```

**macOS**
```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222
```

**Linux**
```bash
google-chrome --remote-debugging-port=9222
```

### 3. Configure AJS
Edit the `config.yaml` file:
- **`whitelist_domains`**: **(IMPORTANT)** Add the domains you intend to analyze (e.g., `example.com`, `localhost`). This is a crucial security measure.
- **`llm_service.api_config`**: Configure the `base_url`, `model_name`, and `api_key` for your chosen LLM service.

### 4. Run AJS
```bash
python main.py
```

Once running, simply use your main Chrome browser. Navigate to the whitelisted page you want to analyze. Perform an action that you suspect triggers encryption (like clicking a login or submit button). Watch the console where you ran AJS. The AI's reverse engineering analysis will be printed there shortly after the event is triggered.
