# tools/check_tcl.py
import sys, os
print("Python executable:", sys.executable)
print("exec_prefix:", sys.exec_prefix)
print("candidate tcl dir:", os.path.join(sys.exec_prefix, "tcl"))
