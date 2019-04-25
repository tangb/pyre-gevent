#!/bin/bash

cd ..
rm -rf dist/
python3 setup.py clean
python3 setup.py sdist
rm -rf pyre_gevent.egg-info
rm -rf build
cd -

