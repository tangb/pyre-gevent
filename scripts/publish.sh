#!/bin/bash
./build.sh
cd ..
python -m twine && python -m twine upload dist/* || twine upload dist/*
cd -

