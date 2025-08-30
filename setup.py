from setuptools import setup, find_packages

setup(
    name='bcl-umj-probe',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'websockets',
        'scapy',
        'requests',
        'psutil',
        'iperf3',
        'pyshark',
        'aiohttp',
        'manuf',
        'pyvis',
        'pysnmp'
    ],
    entry_points={
        'console_scripts': [
            'bcl-umj-probe=bcl_umj_probe.client:run',
        ],
    },
)
