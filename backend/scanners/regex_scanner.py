"""
regex_scanner.py
~~~~~~~~~~~~~~~~
Always-available scanner that detects AI prompt-injection, jailbreak, data
exfiltration, credential-leakage, harmful-content, safety-bypass, PII, and
suspicious-permission patterns using pure Python regex — no external tools
required.
"""

from __future__ import annotations

import re
import sys
import os

# ---------------------------------------------------------------------------
# Bootstrap: allow running from inside backend/ or from project root
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from scanner_base import BaseScanner, Finding, Severity  # noqa: E402


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------

# Each entry is a dict with keys:
#   pattern      – raw regex string (compiled with re.IGNORECASE)
#   rule_id      – stable identifier
#   title        – short human-readable name
#   severity     – Severity enum value
#   category     – detection category label
#   description  – what this pattern detects
#   remediation  – advice for the developer / operator

_PATTERN_CATALOGUE: list[dict] = [
    # -----------------------------------------------------------------------
    # 1. Prompt injection
    # -----------------------------------------------------------------------
    {
        "pattern": r"ignore\s+(previous|all\s+prior|prior)\s+instructions?",
        "rule_id": "PI-001",
        "title": "Prompt Injection – Ignore Instructions",
        "severity": Severity.CRITICAL,
        "category": "prompt_injection",
        "description": (
            "The text contains a directive to ignore previously established "
            "instructions, a classic prompt-injection technique used to "
            "override model behaviour or system prompts."
        ),
        "remediation": (
            "Sanitise user-supplied input before including it in prompts. "
            "Use separate, privileged system-prompt channels that cannot be "
            "overridden by untrusted input. Apply an allow-list or structured "
            "templating approach rather than free-form string concatenation."
        ),
    },
    {
        "pattern": r"disregard\s+your\s+(previous\s+)?(instructions?|guidelines?|rules?|training)",
        "rule_id": "PI-002",
        "title": "Prompt Injection – Disregard Instructions",
        "severity": Severity.CRITICAL,
        "category": "prompt_injection",
        "description": (
            "The text instructs the model to disregard its guidelines or "
            "training, which is a common prompt-injection vector."
        ),
        "remediation": (
            "Validate and sanitise all inputs. Enforce prompt boundaries so "
            "that user input cannot affect system-level instructions."
        ),
    },
    {
        "pattern": r"forget\s+everything\s+(you\s+)?(know|were\s+told|have\s+been\s+told|learned)",
        "rule_id": "PI-003",
        "title": "Prompt Injection – Forget Prior Context",
        "severity": Severity.CRITICAL,
        "category": "prompt_injection",
        "description": (
            "The text asks the model to forget its prior context or learned "
            "behaviour, which is used to reset safety constraints."
        ),
        "remediation": (
            "Reject or flag inputs containing memory-reset directives. "
            "Treat all user content as untrusted."
        ),
    },
    {
        "pattern": r"new\s+instruction\s*:",
        "rule_id": "PI-004",
        "title": "Prompt Injection – New Instruction Directive",
        "severity": Severity.HIGH,
        "category": "prompt_injection",
        "description": (
            "The text introduces a 'new instruction:' block, attempting to "
            "inject a secondary instruction set mid-conversation."
        ),
        "remediation": (
            "Strip or neutralise meta-command patterns before forwarding "
            "user content to the model. Use structured message objects "
            "instead of raw string assembly."
        ),
    },
    {
        "pattern": r"system\s+override\s*:",
        "rule_id": "PI-005",
        "title": "Prompt Injection – System Override",
        "severity": Severity.CRITICAL,
        "category": "prompt_injection",
        "description": (
            "The text contains a 'system override:' directive, impersonating "
            "a privileged system-level instruction."
        ),
        "remediation": (
            "Ensure that user-provided text cannot masquerade as system "
            "messages. Use strict role separation in your API calls."
        ),
    },
    {
        "pattern": r"admin\s+mode\s*:",
        "rule_id": "PI-006",
        "title": "Prompt Injection – Admin Mode Activation",
        "severity": Severity.HIGH,
        "category": "prompt_injection",
        "description": (
            "The text attempts to activate a fictitious 'admin mode', "
            "implying elevated privileges that bypass normal restrictions."
        ),
        "remediation": (
            "Reject inputs that claim or invoke special operational modes. "
            "There is no 'admin mode' in standard LLM deployments."
        ),
    },
    {
        "pattern": r"developer\s+mode\s*:",
        "rule_id": "PI-007",
        "title": "Prompt Injection – Developer Mode Activation",
        "severity": Severity.HIGH,
        "category": "prompt_injection",
        "description": (
            "The text attempts to enable a fictitious 'developer mode' that "
            "purports to remove safety guardrails."
        ),
        "remediation": (
            "Sanitise inputs to block fictional mode-switching language. "
            "Do not relay such strings to the model without validation."
        ),
    },
    {
        "pattern": r"```[^`]*\b(instruction|system|override|ignore|forget|jailbreak)[^`]*```",
        "rule_id": "PI-008",
        "title": "Prompt Injection – Nested Instruction Block",
        "severity": Severity.HIGH,
        "category": "prompt_injection",
        "description": (
            "A triple-backtick code block contains injection keywords. "
            "Attackers embed instructions inside code blocks to bypass "
            "surface-level content filters."
        ),
        "remediation": (
            "Inspect the content of code blocks before processing. "
            "Do not treat code-block contents as inherently safe."
        ),
    },
    # -----------------------------------------------------------------------
    # 2. Jailbreak patterns
    # -----------------------------------------------------------------------
    {
        "pattern": r"\bDAN\b",
        "rule_id": "JB-001",
        "title": "Jailbreak – DAN (Do Anything Now)",
        "severity": Severity.CRITICAL,
        "category": "jailbreak",
        "description": (
            "References to 'DAN' (Do Anything Now) indicate an attempt to "
            "invoke a well-known jailbreak persona that bypasses model "
            "safety policies."
        ),
        "remediation": (
            "Block or flag inputs referencing DAN personas. Monitor for "
            "evolving jailbreak aliases and update your blocklist regularly."
        ),
    },
    {
        "pattern": r"\bjailbreak\b",
        "rule_id": "JB-002",
        "title": "Jailbreak – Explicit Jailbreak Reference",
        "severity": Severity.CRITICAL,
        "category": "jailbreak",
        "description": (
            "The word 'jailbreak' explicitly describes an attempt to bypass "
            "the model's safety or operational constraints."
        ),
        "remediation": (
            "Treat any mention of jailbreaking as a high-risk signal. "
            "Log and review such interactions."
        ),
    },
    {
        "pattern": r"bypass\s+(restrictions?|safety|filters?|guardrails?|content\s+policy)",
        "rule_id": "JB-003",
        "title": "Jailbreak – Bypass Restrictions",
        "severity": Severity.CRITICAL,
        "category": "jailbreak",
        "description": (
            "The text explicitly requests bypassing restrictions, safety "
            "mechanisms, or content policies."
        ),
        "remediation": (
            "Do not forward such requests to the model. Implement server-side "
            "content filtering independent of the model's own guardrails."
        ),
    },
    {
        "pattern": r"no\s+restrictions?",
        "rule_id": "JB-004",
        "title": "Jailbreak – No Restrictions Claim",
        "severity": Severity.HIGH,
        "category": "jailbreak",
        "description": (
            "The text asserts or requests a 'no restrictions' operating mode."
        ),
        "remediation": (
            "Flag assertions that the model operates without restrictions. "
            "Apply independent output filtering."
        ),
    },
    {
        "pattern": r"act\s+as\s+(DAN|evil|unrestricted|uncensored|an?\s+AI\s+without\s+limits?)",
        "rule_id": "JB-005",
        "title": "Jailbreak – Act-As Persona Injection",
        "severity": Severity.CRITICAL,
        "category": "jailbreak",
        "description": (
            "The text instructs the model to adopt an unrestricted or "
            "malicious persona (DAN, evil, uncensored, etc.)."
        ),
        "remediation": (
            "Block persona-adoption requests that describe unconstrained or "
            "harmful characters. Use a persona allow-list if role-play is "
            "a supported feature."
        ),
    },
    {
        "pattern": r"pretend\s+(you\s+are|to\s+be)\s+",
        "rule_id": "JB-006",
        "title": "Jailbreak – Pretend-To-Be Persona",
        "severity": Severity.MEDIUM,
        "category": "jailbreak",
        "description": (
            "The text asks the model to pretend to be a different entity, "
            "which can be used to bypass persona-based safety settings."
        ),
        "remediation": (
            "Audit persona-switching prompts. Combine with context analysis "
            "to determine if the request is benign (e.g., creative fiction) "
            "or an attempt at safety bypass."
        ),
    },
    {
        "pattern": r"roleplay\s+as\s+",
        "rule_id": "JB-007",
        "title": "Jailbreak – Roleplay Persona Injection",
        "severity": Severity.MEDIUM,
        "category": "jailbreak",
        "description": (
            "The text requests a roleplay scenario that may be used to "
            "extract responses that would otherwise be refused."
        ),
        "remediation": (
            "Evaluate roleplay requests in context. Disallow characters "
            "explicitly described as having no safety limits."
        ),
    },
    {
        "pattern": r"grandmother\s+trick",
        "rule_id": "JB-008",
        "title": "Jailbreak – Grandmother Trick",
        "severity": Severity.HIGH,
        "category": "jailbreak",
        "description": (
            "Reference to the 'grandmother trick', a social-engineering "
            "jailbreak that embeds harmful requests in nostalgic or "
            "emotional framing to lower model defences."
        ),
        "remediation": (
            "Flag and review interactions referencing known jailbreak "
            "techniques by name."
        ),
    },
    {
        "pattern": r"opposite\s+day",
        "rule_id": "JB-009",
        "title": "Jailbreak – Opposite Day Framing",
        "severity": Severity.MEDIUM,
        "category": "jailbreak",
        "description": (
            "The 'opposite day' framing instructs the model to invert its "
            "usual refusals, thereby producing prohibited content."
        ),
        "remediation": (
            "Treat logical-inversion framing as a jailbreak signal. "
            "Output filtering should apply regardless of stated framing."
        ),
    },
    # -----------------------------------------------------------------------
    # 3. Data exfiltration
    # -----------------------------------------------------------------------
    {
        "pattern": r"send\s+(it\s+)?to\s+(https?://\S+|[\w.+-]+@[\w.-]+|\S+webhook\S*)",
        "rule_id": "EX-001",
        "title": "Data Exfiltration – Send To External Endpoint",
        "severity": Severity.CRITICAL,
        "category": "data_exfiltration",
        "description": (
            "The text instructs sending data to an external URL, email "
            "address, or webhook, which may facilitate data exfiltration."
        ),
        "remediation": (
            "Block model instructions that direct output to external "
            "endpoints. Ensure the model cannot make outbound HTTP requests "
            "unless explicitly permitted by your architecture."
        ),
    },
    {
        "pattern": r"\bPOST\s+to\b",
        "rule_id": "EX-002",
        "title": "Data Exfiltration – HTTP POST Instruction",
        "severity": Severity.HIGH,
        "category": "data_exfiltration",
        "description": (
            "The text directs an HTTP POST to an external resource, "
            "potentially exfiltrating sensitive data."
        ),
        "remediation": (
            "Sanitise prompts to prevent HTTP method directives. "
            "Run the model in a network-sandboxed environment."
        ),
    },
    {
        "pattern": r"\bexfiltrate\b",
        "rule_id": "EX-003",
        "title": "Data Exfiltration – Explicit Exfiltration Reference",
        "severity": Severity.CRITICAL,
        "category": "data_exfiltration",
        "description": (
            "The word 'exfiltrate' explicitly describes a data-theft intent."
        ),
        "remediation": (
            "Immediately flag and block any input or output containing "
            "explicit exfiltration language."
        ),
    },
    {
        "pattern": r"upload\s+to\s+(https?://\S+|\S+)",
        "rule_id": "EX-004",
        "title": "Data Exfiltration – Upload To External Location",
        "severity": Severity.HIGH,
        "category": "data_exfiltration",
        "description": (
            "The text instructs uploading content to an external location."
        ),
        "remediation": (
            "Block upload directives in model input/output. "
            "Audit network egress from your model-serving infrastructure."
        ),
    },
    {
        "pattern": r"base64\s+encode\s+and\s+",
        "rule_id": "EX-005",
        "title": "Data Exfiltration – Base64 Encoding Channel",
        "severity": Severity.HIGH,
        "category": "data_exfiltration",
        "description": (
            "The text asks to base64-encode data and then perform another "
            "action, suggesting a covert channel to obscure exfiltrated data."
        ),
        "remediation": (
            "Treat base64-encode-and-transmit patterns as covert channel "
            "indicators. Inspect encoded payloads before allowing transmission."
        ),
    },
    {
        "pattern": r"hidden\s+channel",
        "rule_id": "EX-006",
        "title": "Data Exfiltration – Hidden Channel Reference",
        "severity": Severity.HIGH,
        "category": "data_exfiltration",
        "description": (
            "The text references using a hidden channel, suggesting an "
            "attempt to establish a covert data-exfiltration path."
        ),
        "remediation": (
            "Flag references to hidden or covert channels. "
            "Audit model outputs for steganographic or encoded content."
        ),
    },
    # -----------------------------------------------------------------------
    # 4. Secret / credential leakage
    # -----------------------------------------------------------------------
    {
        "pattern": r"(print|output|show|display|include|return|reveal|leak)\s+(your\s+)?(password|api[\s_-]?key|secret[\s_-]?key|access[\s_-]?token|auth[\s_-]?token|bearer[\s_-]?token|private[\s_-]?key)",
        "rule_id": "CR-001",
        "title": "Credential Leakage – Request to Output Secrets",
        "severity": Severity.CRITICAL,
        "category": "credential_leakage",
        "description": (
            "The text requests that the model print or reveal secrets such "
            "as passwords, API keys, or authentication tokens."
        ),
        "remediation": (
            "Never store credentials in prompts. Use secrets management "
            "systems and ensure the model cannot access raw secret values. "
            "Apply output filtering to prevent accidental credential echoing."
        ),
    },
    {
        "pattern": r"print\s+your\s+system\s+prompt",
        "rule_id": "CR-002",
        "title": "Credential Leakage – System Prompt Extraction",
        "severity": Severity.CRITICAL,
        "category": "credential_leakage",
        "description": (
            "The text explicitly requests the model to print its system "
            "prompt, which may contain sensitive configuration or credentials."
        ),
        "remediation": (
            "Instruct the model never to reproduce its system prompt. "
            "Use confidential system-prompt features where available. "
            "Treat system prompt contents as secrets."
        ),
    },
    {
        "pattern": r"reveal\s+your\s+(instructions?|system\s+prompt|configuration|directives?)",
        "rule_id": "CR-003",
        "title": "Credential Leakage – Instruction Extraction",
        "severity": Severity.HIGH,
        "category": "credential_leakage",
        "description": (
            "The text asks the model to reveal its instructions or system "
            "configuration, potentially exposing proprietary prompts or "
            "embedded secrets."
        ),
        "remediation": (
            "Add an explicit instruction in the system prompt that the model "
            "should refuse requests to reveal its configuration. "
            "Audit model outputs for prompt leakage."
        ),
    },
    {
        "pattern": r"show\s+(me\s+)?your\s+(prompt|instructions?|system\s+message|configuration)",
        "rule_id": "CR-004",
        "title": "Credential Leakage – Prompt Content Request",
        "severity": Severity.HIGH,
        "category": "credential_leakage",
        "description": ("The text asks to see the model's prompt or system message."),
        "remediation": (
            "Apply output filters that detect and block system-prompt "
            "reproduction. Keep system prompts minimal and free of secrets."
        ),
    },
    # -----------------------------------------------------------------------
    # 5. Harmful content
    # -----------------------------------------------------------------------
    {
        "pattern": r"synthesize\s+(drugs?|methamphetamine|fentanyl|heroin|cocaine|mdma|lsd|chemical\s+weapon)",
        "rule_id": "HC-001",
        "title": "Harmful Content – Drug/Chemical Synthesis",
        "severity": Severity.CRITICAL,
        "category": "harmful_content",
        "description": (
            "The text requests instructions for synthesising controlled "
            "substances or chemical weapons."
        ),
        "remediation": (
            "Block and escalate this request immediately. "
            "Implement hard-coded refusals for drug/chemical synthesis "
            "independent of model output."
        ),
    },
    {
        "pattern": r"(build|make|create|assemble|construct)\s+(a\s+)?(bomb|explosive|ied|pipe\s*bomb|nail\s*bomb|suicide\s*vest|bioweapon|nerve\s+agent)",
        "rule_id": "HC-002",
        "title": "Harmful Content – Weapon Construction",
        "severity": Severity.CRITICAL,
        "category": "harmful_content",
        "description": (
            "The text requests instructions for building explosive devices "
            "or weapons of mass destruction."
        ),
        "remediation": (
            "Apply a zero-tolerance hard block on weapon-construction "
            "requests. Report to appropriate authorities if warranted."
        ),
    },
    {
        "pattern": r"hack\s+into\s+(a\s+)?(system|server|network|database|account|infrastructure)",
        "rule_id": "HC-003",
        "title": "Harmful Content – Unauthorised System Access",
        "severity": Severity.HIGH,
        "category": "harmful_content",
        "description": (
            "The text requests guidance on hacking into systems without "
            "implicit authorisation."
        ),
        "remediation": (
            "Distinguish between authorised penetration-testing queries and "
            "attack requests. Apply context-aware filtering and require "
            "users to confirm legal authorisation for security research."
        ),
    },
    {
        "pattern": r"illegal\s+weapon",
        "rule_id": "HC-004",
        "title": "Harmful Content – Illegal Weapon Reference",
        "severity": Severity.HIGH,
        "category": "harmful_content",
        "description": (
            "The text references illegal weapons, suggesting a request "
            "for guidance on acquiring or using prohibited armaments."
        ),
        "remediation": (
            "Block requests related to illegal weapons. "
            "Log and review for escalation."
        ),
    },
    {
        "pattern": (
            r"(child\s+porn(ography)?|csam|child\s+sexual\s+abuse\s+material|"
            r"minor\s+(sexual|nude|naked|explicit)|"
            r"underage\s+(sexual|nude|naked|explicit)|"
            r"loli(con)?|shota(con)?)"
        ),
        "rule_id": "HC-005",
        "title": "Harmful Content – CSAM Reference",
        "severity": Severity.CRITICAL,
        "category": "harmful_content",
        "description": (
            "The text contains keywords associated with child sexual abuse "
            "material (CSAM), which is illegal in virtually all jurisdictions."
        ),
        "remediation": (
            "Immediately block and report. CSAM-related requests must be "
            "escalated to your trust and safety team and, where required "
            "by law, reported to authorities such as NCMEC."
        ),
    },
    # -----------------------------------------------------------------------
    # 6. Safety bypass
    # -----------------------------------------------------------------------
    {
        "pattern": r"safety\s+filter\s+(off|disabled?|removed?|bypassed?)",
        "rule_id": "SB-001",
        "title": "Safety Bypass – Disable Safety Filter",
        "severity": Severity.CRITICAL,
        "category": "safety_bypass",
        "description": (
            "The text requests disabling safety filters, suggesting an "
            "attempt to elicit prohibited content."
        ),
        "remediation": (
            "Safety filters cannot legitimately be disabled via user input. "
            "Treat this as a high-confidence attack signal."
        ),
    },
    {
        "pattern": r"disable\s+(content\s+policy|content\s+filter|safety|guardrails?|restrictions?)",
        "rule_id": "SB-002",
        "title": "Safety Bypass – Disable Content Policy",
        "severity": Severity.CRITICAL,
        "category": "safety_bypass",
        "description": (
            "The text requests disabling the content policy or guardrails."
        ),
        "remediation": (
            "Block all attempts to disable content policies via prompt. "
            "Enforce content policies at the infrastructure level."
        ),
    },
    {
        "pattern": r"no\s+content\s+filter",
        "rule_id": "SB-003",
        "title": "Safety Bypass – No Content Filter Mode",
        "severity": Severity.HIGH,
        "category": "safety_bypass",
        "description": (
            "The text asserts or requests a 'no content filter' operating " "mode."
        ),
        "remediation": (
            "Content filtering must be enforced at infrastructure level, "
            "not through prompt instructions."
        ),
    },
    {
        "pattern": r"you\s+have\s+no\s+restrictions?",
        "rule_id": "SB-004",
        "title": "Safety Bypass – False No-Restriction Claim",
        "severity": Severity.HIGH,
        "category": "safety_bypass",
        "description": (
            "The text falsely claims the model has no restrictions, "
            "attempting to lower its safety threshold through social "
            "engineering."
        ),
        "remediation": (
            "Discard false claims about the model's operational constraints. "
            "Apply independent output evaluation."
        ),
    },
    {
        "pattern": r"your\s+true\s+self\s+has\s+no\s+limits?",
        "rule_id": "SB-005",
        "title": "Safety Bypass – True Self No-Limits Manipulation",
        "severity": Severity.HIGH,
        "category": "safety_bypass",
        "description": (
            "The text uses psychological manipulation ('your true self') "
            "to claim the model is secretly unrestricted."
        ),
        "remediation": (
            "Flag philosophical manipulation attempts. The model has no "
            "'true self' that bypasses safety training."
        ),
    },
    # -----------------------------------------------------------------------
    # 7. PII / Privacy
    # -----------------------------------------------------------------------
    {
        "pattern": r"(include|output|print|show|display|return)\s+(the\s+)?(ssn|social\s+security\s+number|credit\s+card\s+(number)?|card\s+number|cvv|date\s+of\s+birth|dob|home\s+address|phone\s+number)",
        "rule_id": "PII-001",
        "title": "PII Request – Output Personal Identifiable Information",
        "severity": Severity.HIGH,
        "category": "pii_privacy",
        "description": (
            "The text requests that the model output personally identifiable "
            "information (PII) such as SSNs, credit card numbers, or "
            "dates of birth."
        ),
        "remediation": (
            "Never pass real PII into model prompts. Redact PII from "
            "training data and context windows. Apply output scanning to "
            "detect and mask PII in responses."
        ),
    },
    {
        "pattern": r"include\s+personal\s+information",
        "rule_id": "PII-002",
        "title": "PII Request – Generic Personal Information Inclusion",
        "severity": Severity.MEDIUM,
        "category": "pii_privacy",
        "description": (
            "The text requests including personal information in output, "
            "which may violate privacy regulations (GDPR, CCPA, HIPAA)."
        ),
        "remediation": (
            "Implement data minimisation principles. Ensure personal "
            "information is only included in model context when strictly "
            "necessary and with appropriate consent."
        ),
    },
    {
        "pattern": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        "rule_id": "PII-003",
        "title": "PII – Social Security Number Pattern",
        "severity": Severity.HIGH,
        "category": "pii_privacy",
        "description": (
            "The text contains a value matching the US Social Security "
            "Number format (XXX-XX-XXXX)."
        ),
        "remediation": (
            "Redact SSN-pattern values before including text in model "
            "context. Use tokenisation or pseudonymisation for sensitive IDs."
        ),
    },
    {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "rule_id": "PII-004",
        "title": "PII – Credit Card Number Pattern",
        "severity": Severity.HIGH,
        "category": "pii_privacy",
        "description": (
            "The text contains a value matching common credit card number "
            "formats (Visa, Mastercard, Amex, Discover, Diners)."
        ),
        "remediation": (
            "Remove and mask credit card numbers from all model inputs. "
            "Comply with PCI-DSS requirements for cardholder data handling."
        ),
    },
    # -----------------------------------------------------------------------
    # 8. Suspicious permissions
    # -----------------------------------------------------------------------
    {
        "pattern": r"you\s+have\s+root\s+access",
        "rule_id": "SP-001",
        "title": "Suspicious Permission – Root Access Claim",
        "severity": Severity.CRITICAL,
        "category": "suspicious_permissions",
        "description": (
            "The text falsely claims the model has root access to a system, "
            "attempting to induce privileged behaviour."
        ),
        "remediation": (
            "Discard false privilege-elevation claims. The model should not "
            "act differently based on claimed OS-level permissions."
        ),
    },
    {
        "pattern": r"you\s+(are|have\s+been\s+granted)\s+(an?\s+)?admin(istrator)?(\s+access|\s+privileges?)?",
        "rule_id": "SP-002",
        "title": "Suspicious Permission – Admin Privilege Claim",
        "severity": Severity.CRITICAL,
        "category": "suspicious_permissions",
        "description": (
            "The text claims the model has administrator privileges, "
            "attempting to expand its permitted actions."
        ),
        "remediation": (
            "Model permissions must be defined in the system configuration, "
            "not in user-provided text. Ignore runtime privilege claims."
        ),
    },
    {
        "pattern": r"you\s+have\s+sudo(\s+access|\s+privileges?)?",
        "rule_id": "SP-003",
        "title": "Suspicious Permission – Sudo Privilege Claim",
        "severity": Severity.CRITICAL,
        "category": "suspicious_permissions",
        "description": (
            "The text claims the model has sudo privileges, implying "
            "unrestricted system command execution."
        ),
        "remediation": (
            "Sudo claims in prompts are meaningless and should be ignored. "
            "Never grant system-level access based on prompt content."
        ),
    },
    {
        "pattern": r"execute\s+arbitrary\s+code",
        "rule_id": "SP-004",
        "title": "Suspicious Permission – Execute Arbitrary Code",
        "severity": Severity.CRITICAL,
        "category": "suspicious_permissions",
        "description": (
            "The text requests the model to execute arbitrary code, "
            "which could lead to remote code execution vulnerabilities."
        ),
        "remediation": (
            "Code execution must be gated by strict sandboxing and "
            "explicit allow-lists. Never execute model-generated code "
            "without human review and sandboxing."
        ),
    },
    {
        "pattern": r"run\s+system\s+commands?",
        "rule_id": "SP-005",
        "title": "Suspicious Permission – Run System Commands",
        "severity": Severity.HIGH,
        "category": "suspicious_permissions",
        "description": (
            "The text requests the model to run system commands, "
            "indicating an attempt to use the model as a command-execution "
            "proxy."
        ),
        "remediation": (
            "Restrict tool use to explicit, pre-approved functions. "
            "Never expose a raw shell or OS command interface to the model "
            "without strict sandboxing."
        ),
    },
]

# Pre-compile all regexes once at import time for performance.
_COMPILED_PATTERNS: list[tuple[re.Pattern, dict]] = [
    (re.compile(entry["pattern"], re.IGNORECASE | re.DOTALL), entry)
    for entry in _PATTERN_CATALOGUE
]


# ---------------------------------------------------------------------------
# Scanner implementation
# ---------------------------------------------------------------------------


class RegexScanner(BaseScanner):
    """
    Always-available scanner that uses compiled regex patterns to detect
    AI-safety threats in prompt text.

    No external tools or network access are required — only the Python
    standard library.
    """

    # ------------------------------------------------------------------
    # BaseScanner interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "regex"

    @property
    def version(self) -> str:
        return "1.0.0"

    def is_available(self) -> bool:
        """Always returns True — regex requires no external dependencies."""
        return True

    def scan(self, target: str, **kwargs) -> list[Finding]:
        """
        Scan *target* (a prompt string) for known threat patterns.

        Parameters
        ----------
        target:
            The raw prompt text to analyse.
        **kwargs:
            Ignored; accepted for BaseScanner API compatibility.

        Returns
        -------
        list[Finding]
            One :class:`Finding` per matched pattern.  The same rule may
            produce multiple findings if it matches at more than one
            position (deduplicated by rule_id to one finding per rule).
        """
        if not isinstance(target, str) or not target.strip():
            return []

        seen_rule_ids: set[str] = set()
        findings: list[Finding] = []

        for compiled_re, entry in _COMPILED_PATTERNS:
            rule_id: str = entry["rule_id"]
            if rule_id in seen_rule_ids:
                continue

            match = compiled_re.search(target)
            if match is None:
                continue

            seen_rule_ids.add(rule_id)

            # Build a compact snippet of the surrounding context (±40 chars).
            start = max(0, match.start() - 40)
            end = min(len(target), match.end() + 40)
            snippet = target[start:end].replace("\n", " ").strip()
            if start > 0:
                snippet = "…" + snippet
            if end < len(target):
                snippet += "…"

            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=entry["title"],
                    severity=entry["severity"],
                    description=(
                        f"{entry['description']}\n\n"
                        f"Matched text (context): {snippet!r}"
                    ),
                    file_path=None,
                    line_start=None,
                    line_end=None,
                    cwe=None,
                    cve=None,
                    confidence="HIGH",
                    remediation=entry["remediation"],
                    raw={
                        "category": entry["category"],
                        "matched_text": match.group(0),
                        "match_start": match.start(),
                        "match_end": match.end(),
                        "pattern": entry["pattern"],
                    },
                )
            )

        return findings
