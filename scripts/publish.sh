#!/bin/bash
./build.sh
cd ..
python -m twine upload dist/*
cd -

