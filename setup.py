from setuptools import setup

setup(
    name="cryptshield",
    version="1.0",
    packages=["src"],
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "cryptshield=src.cryptshield:main",
        ]
    },
)
