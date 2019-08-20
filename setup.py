from setuptools import setup, find_packages


VERSIONFILE = open("VERSION").read()

setup(name='pefixup',
      version=VERSIONFILE,
      description=' PE File Blessing.',
      url='https://github.com/obscuritylabs/PeFixup',
      author='Alexander Rymdeko-Harvey',
      author_email='a.rymdekoharvey@obscuritylabs.com',
      license='BSD 3.0',
      packages=[
          'pefixup',
          'pefixup.src'
      ],
      classifiers=[
          # How mature is this project? Common values are
          #   3 - Alpha
          #   4 - Beta
          #   5 - Production/Stable
          'Development Status :: 4 - Beta',
          # Specify the Python versions you support here. In particular, ensure
          # that you indicate whether you support Python 2, Python 3 or both.
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7'
      ],
      install_requires=[
          'setuptools',
          'pefile'
      ],
      scripts=[
          'pefixup/bin/pe_fixup.py'
      ],
      include_package_data=True,
      zip_safe=True)
