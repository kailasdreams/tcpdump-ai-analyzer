"""
ai_engine.py  –  Unified AI routing for TCPDump Analyzer
Supports: Anthropic Claude  |  OpenAI GPT
"""

SYSTEM_PROMPT = """You are a senior network security engineer with deep expertise in:
- F5 BIG-IP / LTM / GTM / ASM
- TCP/IP protocol analysis and troubleshooting
- SSL/TLS handshake failure diagnosis
- Network latency, retransmits, and RST analysis
- Firewall and load-balancer behaviour

Analyze the provided TCPDump / packet capture output and return a structured report with:

## Executive Summary
One-paragraph plain-English summary of what you found.

## Observed Issues
Bullet list of every anomaly detected (connection resets, retransmits, SSL errors, etc.).

## Root Cause Analysis
Explain the most likely root cause(s) with evidence from the packet data.

## Recommended Fixes
Numbered, actionable steps an engineer can take immediately.

## Severity
Rate overall severity: CRITICAL / HIGH / MEDIUM / LOW and explain why.

Be concise, precise, and technical. Avoid generic advice not supported by the data."""


def analyze_with_ai(tcpdump_data: str, provider: str, model: str, api_key: str):
    """
    Returns (response_text, error_message).
    On success: (str, None)
    On failure: (None, str)
    """
    try:
        if provider == "anthropic":
            return _call_anthropic(tcpdump_data, model, api_key)
        elif provider == "openai":
            return _call_openai(tcpdump_data, model, api_key)
        else:
            return None, f"Unknown provider: {provider}"
    except Exception as exc:
        return None, f"Unexpected error: {exc}"


# ── Anthropic ──────────────────────────────────────────────────────────────────

def _call_anthropic(data: str, model: str, api_key: str):
    try:
        import anthropic
    except ImportError:
        return None, "anthropic package not installed. Run: pip install anthropic"

    client = anthropic.Anthropic(api_key=api_key)
    user_content = f"Analyze the following TCPDump output:\n\n```\n{data[:30000]}\n```"

    try:
        msg = client.messages.create(
            model=model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        return msg.content[0].text, None
    except anthropic.AuthenticationError:
        return None, "Authentication failed – check your Anthropic API key."
    except anthropic.APIError as e:
        return None, f"Anthropic API error: {e}"


# ── OpenAI ─────────────────────────────────────────────────────────────────────

def _call_openai(data: str, model: str, api_key: str):
    try:
        import openai
    except ImportError:
        return None, "openai package not installed. Run: pip install 'openai>=1.0.0'"

    user_content = f"Analyze the following TCPDump output:\n\n```\n{data[:30000]}\n```"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_content},
    ]

    # ── openai v1.x (preferred) ────────────────────────────────────
    if hasattr(openai, "OpenAI"):
        client = openai.OpenAI(api_key=api_key)
        try:
            resp = client.chat.completions.create(
                model=model, max_tokens=2048, messages=messages,
            )
            return resp.choices[0].message.content, None
        except openai.AuthenticationError:
            return None, "Authentication failed – check your OpenAI API key."
        except openai.APIError as e:
            return None, f"OpenAI API error: {e}"

    # ── openai v0.x fallback ───────────────────────────────────────
    else:
        openai.api_key = api_key
        try:
            resp = openai.ChatCompletion.create(
                model=model, max_tokens=2048, messages=messages,
            )
            return resp["choices"][0]["message"]["content"], None
        except openai.error.AuthenticationError:
            return None, "Authentication failed – check your OpenAI API key."
        except openai.error.OpenAIError as e:
            return None, f"OpenAI API error: {e}"
