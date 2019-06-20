cython Nemesis.pyx -a -3

gcc -c -IC:"J:\PROGRAMMING\Python3\include" -o temp.o Nemesis.c
gcc -shared -LC:"J:\PROGRAMMING\Python3\libs" -o Nemesis.pyd temp.o "J:\PROGRAMMING\Python3\libs\libpython37.a"

del Nemesis.c
del temp.o
PAUSE