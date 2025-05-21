#!/bin/bash

if ! test -f ~/.pypirc; then
  echo "~/.pypirc config file does not exist. Please add it with pyre-gevent repository entry"
fi

./build.sh
cd ..
python -m twine --version && python -m twine upload --repository pyre-gevent dist/*
cd -

