# Function: IDA Plugin, to export all (pseudocode) code to file
# Author: CrifanLi
# Update: 20260116
# Usage:
# IDA Pro -> File -> Script file ... -> (Double click to ) Run this script: `idaExportAllCode.py` -> got `xxx_20260115_115035_allCode.m`

import idaapi
import idautils
import ida_hexrays

import os
from datetime import datetime,timedelta

################################################################################
# Config
################################################################################

isExitIdaAfterDone = False

exportedFileSuffix = "allCode.m"

oututSubFolderName = "exportedAllCode"

################################################################################
# Util
################################################################################

def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
  """
  get current datetime then format to string

  eg:
      20171111_220722

  :param outputFormat: datetime output format
  :return: current datetime formatted string
  """
  curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
  curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
  return curDatetimeStr

def createFolder(folderFullPath):
  """
  create folder, even if already existed
  Note: for Python 3.2+
  """
  os.makedirs(folderFullPath, exist_ok=True)

################################################################################
# Main
################################################################################

def main():
  curDatetimeStr = getCurDatetimeStr()
  print("curDatetimeStr=%s" % curDatetimeStr)

  # 1. 等待 IDA 自动分析完成
  print("Waiting for auto-analysis to finish...")
  idaapi.auto_wait()

  # 2. 检查 Hex-Rays 插件是否可用
  if not ida_hexrays.init_hexrays_plugin():
    print("Hex-Rays decompiler is not available.")
    idaapi.qexit(1)

  # 3. 设置导出文件路径和文件名
  inputFileFullPath = idaapi.get_input_file_path()
  print("inputFileFullPath=%s" % inputFileFullPath)
  inputFilename = os.path.basename(inputFileFullPath)
  inputPath = os.path.dirname(inputFileFullPath)
  print("inputFilename=%s" % inputFilename)
  print("inputPath=%s" % inputPath)

  outputFilename = "%s_%s_%s" % (inputFilename, curDatetimeStr, exportedFileSuffix)
  print("outputFilename=%s" % outputFilename)

  outputSubFolder = os.path.join(inputPath, oututSubFolderName)
  print("outputSubFolder=%s" % outputSubFolder)
  createFolder(outputSubFolder)

  outputFullPath = os.path.join(outputSubFolder, outputFilename)
  print("outputFullPath=%s" % outputFullPath)

  # 4. 开始导出所有函数位代码
  print(f"Exporting pseudocode to: {outputFullPath}")
  with open(outputFullPath, "w", encoding="utf-8") as f:
    # 遍历所有函数
    for ea in idautils.Functions():
      func_name = idaapi.get_func_name(ea)
      try:
        # 反编译函数
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
          f.write(f"// Function: {func_name} @ {hex(ea)}\n")
          f.write(str(cfunc) + "\n\n")
        else:
          f.write(f"// [Error] Could not decompile: {func_name}\n")
      except Exception as e:
        f.write(f"// [Exception] Failed to decompile {func_name}: {str(e)}\n")

  print(f"Exported all code to: {outputFullPath}")
  # print("Export finished! Exiting...")

  if isExitIdaAfterDone:
    # 4. 导出完成后自动退出 IDA
    idaapi.qexit(0)

if __name__ == "__main__":
  main()