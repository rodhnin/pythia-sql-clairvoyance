"""
Setup script for Pythia SQL Injection Scanner.

Install:
    pip install -e .

Or:
    python setup.py install

Author: Rodney Dhavid Jimenez Chacin (rodhnin)
License: MIT
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
if readme_file.exists():
    with readme_file.open('r', encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = "Pythia - Passive SQL Injection Detection Scanner"

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    with requirements_file.open('r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
else:
    requirements = [
        'requests>=2.31.0',
        'pyyaml>=6.0',
        'beautifulsoup4>=4.12.0',
        'Jinja2>=3.1.0',
    ]

setup(
    name='pythia-scanner',
    version='0.1.0',
    description='Passive SQL Injection Detection Scanner',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Rodney Dhavid Jimenez Chacin',
    url='https://github.com/rodhnin/pythia-sql-clairvoyance',
    license='MIT',
    
    # Package structure
    packages=find_packages(exclude=['tests', 'tests.*', 'docs', 'examples']),
    package_data={
        'pyth': [
            '../assets/ascii.txt',
            '../config/defaults.yaml',
            '../config/prompts/*.txt',
            '../templates/*.j2',
            '../schema/*.json',
            '../db/*.sql',
        ],
    },
    include_package_data=True,
    
    # Dependencies
    install_requires=requirements,
    
    # Optional dependencies
    extras_require={
        'ai': [
            'langchain-core>=1.0.0',
            'langchain-openai>=1.0.0',
            'langchain-anthropic>=1.0.0',
            'langchain-ollama>=0.3.0',
        ],
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
    },
    
    # Entry points
    entry_points={
        'console_scripts': [
            'pythia=pyth.cli:main',
            'pyth=pyth.cli:main',
        ],
    },
    
    # Classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
    ],
    
    # Python version
    python_requires='>=3.8',
    
    # Keywords
    keywords='security sql-injection scanner penetration-testing vulnerability-scanner',
    
    # Project URLs
    project_urls={
        'Bug Reports': 'https://github.com/rodhnin/pythia-sql-clairvoyance/issues',
        'Source': 'https://github.com/rodhnin/pythia-sql-clairvoyance',
        'Website': 'https://rodhnin.com',
    },
)