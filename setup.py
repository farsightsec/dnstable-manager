from setuptools import setup, find_packages

setup(
    name = 'dnstable-manager',
    version = '1.0.0',
    packages = find_packages(),

    scripts = ['dnstable-manager'],
    install_requires = [
        'functools32',
        'jsonschema >=2.3.0',
        'option_merge',
        'psutil',
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
