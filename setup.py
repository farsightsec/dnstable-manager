from setuptools import setup, find_packages

setup(
    name = 'dnstable-manager',
    version = '0.5',
    packages = find_packages(),

    scripts = ['dnstable-manager'],
    requires = [
        'functools32',
        'jsonschema',
        'option_merge',
        'PyYAML',
        'setuptools',
        'terminable_thread',
        ],

    package_data = {
        'dnstable_manager': ['*.yaml'],
    },

    test_suite='dnstable_manager',

    author = 'Farsight Security Inc.',
    author_email = 'software@fsi.io',

    zip_safe = True,
)
