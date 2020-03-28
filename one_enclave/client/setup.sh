#!/bin/bash
virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 -m grpc_tools.protoc -I../proto --python_out=. --grpc_python_out=. ../proto/secretsharing.proto