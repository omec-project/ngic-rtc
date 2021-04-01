#!/bin/bash

apt-get install python3-pip -y
apt-get install python3-virtualenv -y
virtualenv -p python3.5 venv
source venv/bin/activate
pip install -r requirements.txt
