# STIGmatism
A tool to simplify modification of DISA STIG checklist files.

This tool can be used to automate modification of certain XML elements inside of a DISA STIG checklist file (.ckl).
By using the '--match' and '--change' options, elements, such as 'STATUS', 'FINDING_DETAILS', and 'COMMENTS' can be found
and/or modified.

Please run 'python stigmatism.py --help' to see an updated list of options and features.

*Note:
This script was tested and developed with a Python v3.x interpreter. As such, it may not run correctly with earlier versions of the Python interpreter.
