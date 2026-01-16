# idaExportAllCode

* Update: `20260116`

## Function

IDA Plugin, to export all (pseudocode) code to file

## Git Repo

https://github.com/crifan/idaExportAllCode

https://github.com/crifan/idaExportAllCode.git

## Usage

`IDA Pro` -> `File` -> `Script file ...` -> (Double click to ) Run this script: `idaExportAllCode.py` -> got exported file (in folder of same with input binary), eg: `exportedAllCode/xxx_20260115_115035_allCode.m`

## TODO

* [ ] split exported each function into single file
  * eg: save some function into: `+[NetworkMonitor setHostEndRegString:].m`, `sub_1413C.m`, `objc_msgSend_substringToIndex_.m`, etc.
