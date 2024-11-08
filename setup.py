from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="termhound",
    version="1.0.0",
    author="Security Researcher",
    description="Active Directory Security Analysis Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "neo4j>=5.14.1",
        "colorama>=0.4.6",
        "pandas>=2.1.3",
        "rich>=13.7.0",
        "typing-extensions>=4.8.0",
        "python-dateutil>=2.8.2"
    ],
    entry_points={
        "console_scripts": [
            "termhound=termhound.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
