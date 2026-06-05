from setuptools import setup, find_packages

setup(
    name="agentsentry",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.22.0",
        "pydantic>=2.0",
        "networkx>=3.0",
        "click>=8.0",
    ],
    entry_points={
        "console_scripts": [
            "agentsentry=agentsentry.cli:main",
        ],
    },
)
