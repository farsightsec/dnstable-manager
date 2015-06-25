from setuptools import setup, find_packages

setup(
    name = 'dnstable-manager',
    version = '0.1',
    packages = find_packages(),

    scripts = ['dnstable-manager'],

    test_suite='dnstable_manager',

    author = 'Farsight Security Inc.',
    author_email = 'software@fsi.io',
)