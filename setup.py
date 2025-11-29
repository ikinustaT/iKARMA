"""
iKARMA - IOCTL Kernal Artifact Risk Mapping & Analysis

Production Release v2.0.1
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

setup(
    name="ikarma",
    version="2.0.1",
    author="iKARMA Team",
    author_email="ikarma@example.com",
    description="IOCTL Kernal Artifact Risk Mapping & Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/ikarma",
    license="MIT",
    
    packages=find_packages(exclude=["tests", "tests.*", "examples", "docs"]),
    
    python_requires=">=3.8",
    
    install_requires=[
        "pefile>=2023.2.7",
        "capstone>=5.0.0",
    ],
    
    extras_require={
        "volatility": [
            "volatility3>=2.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
        "all": [
            "volatility3>=2.0.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    
    entry_points={
        "console_scripts": [
            "ikarma=ikarma.cli:main",
        ],
    },
    
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: System :: Operating System Kernels",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    
    keywords=[
        "memory forensics",
        "kernel driver",
        "malware analysis",
        "DFIR",
        "volatility",
        "windows",
        "security",
    ],
    
    project_urls={
        "Documentation": "https://github.com/example/ikarma/docs",
        "Source": "https://github.com/example/ikarma",
        "Tracker": "https://github.com/example/ikarma/issues",
    },
)
