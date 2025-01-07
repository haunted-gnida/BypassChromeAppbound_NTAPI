@echo off

cls

cl /EHsc /MD main.c src/sqlite3.c

DEL main.obj
