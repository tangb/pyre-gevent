#!/bin/bash

cd ..
rm -rf dist/
python3 setup.py clean
python3 setup.py sdist
python3 setup.py bdist_wheel --universal
rm -rf pyre_gevent.egg-info
rm -rf build
cd -

