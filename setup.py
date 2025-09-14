"""
Setup script for InvestiGUI Digital Forensics Toolkit
"""

from setuptools import setup, find_packages
from version import get_version, get_full_version

# Read README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements file
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

version_info = get_full_version()

setup(
    name="investigui",
    version=get_version(),
    author="InvestiGUI Team",
    author_email="contact@investigui.org",
    description="Advanced Digital Forensics Toolkit with GUI and Machine Learning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/irfan-sec/InvestiGUI",
    project_urls={
        "Bug Tracker": "https://github.com/irfan-sec/InvestiGUI/issues",
        "Documentation": "https://github.com/irfan-sec/InvestiGUI/wiki",
        "Source Code": "https://github.com/irfan-sec/InvestiGUI",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Legal Industry",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: X11 Applications :: Qt",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-qt>=4.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.910",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=0.5",
        ],
        "analysis": [
            "scikit-learn>=1.0",
            "matplotlib>=3.3",
            "seaborn>=0.11",
            "plotly>=5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "investigui=main:main",
            "investigui-cli=main:start_cli_mode",
            "investigui-demo=demo:main",
        ],
    },
    include_package_data=True,
    package_data={
        "investigui": [
            "plugins/*.py",
            "examples/*",
            "docs/*",
        ],
    },
    keywords=[
        "digital forensics", "incident response", "security analysis",
        "log analysis", "artifact extraction", "timeline analysis",
        "machine learning", "anomaly detection", "cybersecurity",
        "forensic investigation", "evidence analysis"
    ],
    platforms=["Windows", "Linux", "macOS"],
    zip_safe=False,
)