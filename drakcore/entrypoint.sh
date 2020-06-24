#!/bin/bash

case $1 in
    "system" )
        drak-system;;
    "postprocess" )
        drak-postprocess;
esac

