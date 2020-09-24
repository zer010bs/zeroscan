#!/bin/bash
#
#

vdir="venv" 


echo "

APP_INSTALLER 

"
echo "[i] Initializing " 

if [ -d "$vdir" ]; then
echo "  >  old venv found, creating new" 
    rm -Rf $vdir
fi
echo "  >  installing new virtual-env in $vdir" 

echo ">  installing virtualenv in $vdir" 
virtualenv -p python3 $vdir


. $vdir/bin/activate

echo ">  installing requirements" 


pip3 install --upgrade simplejson
pip3 install --upgrade python-libnmap
pip3 install --upgrade cpe
pip3 install --upgrade cvss
pip3 install --upgrade impacket



