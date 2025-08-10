from setuptools import setup, find_packages

setup(
    name="cryptshield",
    version="1.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "cryptshield=cryptshield.cryptshield:main",
        ]
    },
)
