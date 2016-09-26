from setuptools import find_packages
from setuptools import setup

MAJOR_VERSION = '0'
MINOR_VERSION = '0'
MICRO_VERSION = '5'
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
      zip_safe=False,
      platforms='any')
