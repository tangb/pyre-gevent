#!/bin/bash

cd ..
rm -rf dist/
python -m build --outdir dist/ --wheel --sdist 
rm -rf pyre_gevent.egg-info
rm -rf build
cd -

