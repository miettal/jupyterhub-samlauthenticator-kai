"""jupyterhub-samlauthenticator package."""
from setuptools import setup


setup(
    name='jupyterhub-samlauthenticator',
    packages=['samlauthenticator'],
    install_requires=[
        'Jinja2>=2.4',
        'jupyterhub>=0.9.0',
        'lxml>=4.2.1',
        'signxml>=2.6.0',
        'pytz>=2019.1',
        'pysaml2>=7.4',
    ],
    extras_require={'tests': [
        'pytest>=4.0.0',
        'pytest-asyncio>=0.10.0',
        'pytest-cov>=2.0.0',
    ]},
)
