from setuptools import find_packages
from setuptools import setup

MAJOR_VERSION = '0'
MINOR_VERSION = '2'
MICRO_VERSION = '39'
VERSION = "{}.{}.{}".format(MAJOR_VERSION, MINOR_VERSION, MICRO_VERSION)

setup(name='access_points',
      version=VERSION,
      description="Scan your WiFi and get access point information and signal quality.",
      url='https://github.com/kootenpv/access_points',
      author='Pascal van Kooten',
      author_email='kootenpv@gmail.com',
      entry_points={
          'console_scripts': ['access_points = access_points.__init__:main']
      },
      license='MIT',
      packages=find_packages(),
      package_data={'data': ['*.txt']},
      include_package_data=True,
      classifiers=[
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: Customer Service',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Operating System :: Microsoft',
          'Operating System :: MacOS :: MacOS X',
          'Operating System :: Unix',
          'Operating System :: POSIX',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Software Development',
          'Topic :: Software Development :: Build Tools',
          'Topic :: Software Development :: Debuggers',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Software Distribution',
          'Topic :: System :: Systems Administration',
          'Topic :: Utilities'
      ],
      zip_safe=False,
      platforms='any')
