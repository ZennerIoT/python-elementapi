from distutils.core import setup

setup(
  name='elementapi',
  packages=['elementapi'],
  version='0.3.9',
  description='element-iot api client lib',
  author='Stefan Reiser',
  author_email='sr@zenner-iot.com',
  url='https://github.com/ZennerIoT/python-elementapi',
  download_url='https://github.com/ZennerIoT/python-elementapi/archive/master.zip',
  keywords=['client', 'rest', 'element-iot'],
  classifiers =[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
  ],
  install_requires=['requests']
)
