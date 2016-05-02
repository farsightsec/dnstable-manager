from setuptools import setup, find_packages

setup(
    name = 'dnstable-manager',
    version = '0.8.0',
    packages = find_packages(),

    scripts = ['dnstable-manager'],
    requires = [
        'functools32',
        'jsonschema (>=2.3.0)',
        'option_merge',
        'PyYAML',
        'setuptools',
        'terminable_thread',
        ],

    package_data = {
        'dnstable_manager': ['*.yaml'],
    },

    test_suite='tests',
    tests_require = [
        'pyflakes',
        ],

    author = 'Farsight Security Inc.',
    author_email = 'software@fsi.io',

    zip_safe = True,
)
