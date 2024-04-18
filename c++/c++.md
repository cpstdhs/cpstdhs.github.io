# 🚀 C++
> c++ 공부 내용 + 리버싱

# Category
- [🚀 C++](#-c)
- [Category](#category)

```c
std::cout << "a: " << a << std::endl;
```
```
00007FF7F0031030  lea         rdx,[__xmm@ffffffffffffffffffffffffffffffff+10h (07FF7F00332F0h)]  
00007FF7F0031037  mov         rcx,qword ptr [__imp_std::cout (07FF7F00330A0h)]  
00007FF7F003103E  call        std::operator<<<std::char_traits<char> > (07FF7F0031360h)  
00007FF7F0031043  mov         edx,dword ptr [a]  
00007FF7F0031047  mov         rcx,rax  
00007FF7F003104A  call        qword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (07FF7F0033098h)]  
00007FF7F0031050  lea         rdx,[std::endl<char,std::char_traits<char> > (07FF7F0031730h)]  
00007FF7F0031057  mov         rcx,rax  
00007FF7F003105A  call        qword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (07FF7F00330A8h)]
```