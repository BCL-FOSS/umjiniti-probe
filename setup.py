from setuptools import setup, find_packages

setup(
    name="bcl-umj-probe",
    version="1.0.0",
    description="open source probe enabling agentic AI automation into any production network.",
    author="Baugh Consulting & Lab L.l.C.",
    packages=find_packages(where=".", exclude=("tests", "tests.*")),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "fastapi",
        "uvicorn[standard]",
        "websockets",
        "scapy",
        "requests",
        "psutil",
        "iperf3",
        "pyshark",
        "aiohttp",
        "manuf",
        "pyvis",
        "pysnmp",
    ],
    # no console_scripts: systemd/rc.d call uvicorn directly
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
