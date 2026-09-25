from setuptools import setup, find_packages

setup(
    name="safegguf",
    version="0.3.6",
    description="Memory-Safe GGUF v3 Structural & Arithmetic Validator Python Bindings",
    author="SafeGGUF Contributors",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
