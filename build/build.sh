#!/bin/bash
CC=clang CXX=clang python3 ../configure.py -s tf2 --mms-path=../../../../mmsource-1.11/
ambuild
