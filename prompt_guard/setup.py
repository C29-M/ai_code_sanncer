from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="prompt-guard",
    version="0.1.0",
    author="AI Security Team",
    description="AI security middleware for scanning system prompts",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
    ],
    extras_require={
        "garak": ["garak"],
        "guardrails": ["guardrails-ai"],
        "nemo": ["nemoguardrails"],
        "dev": ["pytest>=7.0", "pytest-cov>=4.0"],
        "all": ["garak", "guardrails-ai", "nemoguardrails"],
    },
    entry_points={
        "console_scripts": [
            "prompt-guard=prompt_guard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="ai security prompt injection jailbreak llm safety middleware",
)
