from setuptools import setup

setup(
    name="guardian",
    version="1.0",
    packages=["src"],
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "guardian=src.guardian:main",
        ]
    },
)
