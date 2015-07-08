from setuptools import setup, find_packages

setup(
    name='pycalico',

    # Don't need a version until we publish to PIP or other forum.
    # version='0.0.0',

    description='A Python API to Calico',

    # The project's main homepage.
    url='https://github.com/Metaswitch/calico-docker/',

    # Author details
    author='Project Calico',
    author_email='calico-tech@lists.projectcalico.org',

    # Choose your license
    license='Apache 2.0',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Networking',
    ],

    # What does your project relate to?
    keywords='calico docker etcd mesos kubernetes rkt openstack',

    package_dir={"": "calico_containers"},
    packages=["pycalico"],

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['netaddr', 'python-etcd'],

)
