# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import httpie_dag

try:
    import multiprocessing
except ImportError:
    pass


setup(
    name='httpie-dag',
    description='HTTPie plugin for IIJ GIO Storage & Analysis Service(DAG).',
    version=httpie_dag.__version__,
    author=httpie_dag.__author__,
    author_email=httpie_dag.__author_email__,
    license=httpie_dag.__license__,
    url='https://github.com/iij/httpie-dag',
    packages=find_packages(),
    zip_safe=False,
    test_suite = 'nose.collector',
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_auth_dag = httpie_dag.auth:DAGAuthPlugin',
            'httpie_auth_aws = httpie_dag.auth:AWSAuthPlugin',
            'httpie_auth_dag_v4 = httpie_dag.auth_v4:DAGSignatureV4AuthPlugin',
            'httpie_auth_aws_v4 = httpie_dag.auth_v4:AWSSignatureV4AuthPlugin',
        ]
    },
    install_requires=[
        'httpie>=0.9.6'
    ],
    tests_require = [
        'nose',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python',
        'Environment :: Plugins',
        'License :: OSI Approved :: BSD License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Utilities'
    ],
)
