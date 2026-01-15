# Function: IDA Plugin, to export all (pseudocode) code to file
# Author: CrifanLi
# Update: 20260115
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

  # 3. 设置导出文件路径
  # 默认保存在 dylib 同级目录下，名为 exported_code.m
  input_path = idaapi.get_input_file_path()
  print("input_path=%s" % input_path)
  inputFileName = os.path.splitext(input_path)[0]
  print("fileNainputFileNameme=%s" % inputFileName)
  outputFilename = "%s_%s_%s" % (inputFileName, curDatetimeStr, exportedFileSuffix)

  print(f"Exporting pseudocode to: {outputFilename}")

  with open(outputFilename, "w", encoding="utf-8") as f:
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

  print("Export finished! Exiting...")

  if isExitIdaAfterDone:
    # 4. 导出完成后自动退出 IDA
    idaapi.qexit(0)

if __name__ == "__main__":
  main()