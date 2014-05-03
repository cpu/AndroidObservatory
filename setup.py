from setuptools import setup

setup(
  name='Android Observatory',
  version='0.2',
  long_description=__doc__,
  packages=['observatory'],
  include_package_data=True,
  zip_safe=False,
  install_requires=[
    'Flask>=0.9',
    'Flask-Uploads',
  ]
)

