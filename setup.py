from setuptools import setup, find_packages


setup(
    long_description=open("README.md", "r").read(),
    name="wifuzz",
    version="0.1",
    description="wireless fuzzer",
    author="Pascal Eberlein",
    author_email="pascal@eberlein.io",
    url="https://github.com/nbdy/wifuzz",
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
    install_requires=[
        "scapy",
        "pyrunnable",
        "netifaces",
        "mac_vendor_lookup",
        "terminaltables",
        "progressbar2",
        "btpy==2.0.3",
        "loguru"
    ],
    entry_points={
        'console_scripts': [
            'wifuzz = wifuzz.__main__:main'
        ]
    },
    keywords="fuzzing",
    packages=find_packages(),
    long_description_content_type="text/markdown"
)
