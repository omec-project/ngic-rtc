#!/bin/bash

apt-get install python-pip
apt-get install python-virtualenv
virtualenv -p python3.5 venv
source venv/bin/activate
pip install -r requirements.txt


