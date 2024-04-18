# 👩‍🎓 ida
> idapython, ida plugin, flirt 등 ida 기능 및 확장 정리

# Category
- [👩‍🎓 ida](#-ida)
- [Category](#category)
  - [Plugin](#plugin)
  - [FLIRT](#flirt)
  - [IDAPython](#idapython)
  - [jmp idiom to switch idiom](#jmp-idiom-to-switch-idiom)

## Plugin

## FLIRT

## IDAPython

## jmp idiom to switch idiom
```py
table = 0x0000555555557020 # jmp table
6 # switch num
4 # jmp table element length
start switch idiom = 0x0000555555555678 # start of switch idiom
rax # Input Register of Switch
0 # First Input Value
0x00005555555556C9 # Default Jump Address
```