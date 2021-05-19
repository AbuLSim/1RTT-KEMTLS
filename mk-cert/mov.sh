#!/bin/bash
rm *.bin
mv *.key *.crt *.pub *.sig ../certificates
rm -rf __pycache__
