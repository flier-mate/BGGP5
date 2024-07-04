;BGGP5 (ELF32) - 155 bytes
;@fliermate
;
; Jul 4, 2024
;
; Expected command: wget -q https://binary.golf/5/5 && cat 5
;
; This is an incomplete program because currently it only calls GNU Wget without displaying
; the downloaded file "5".
;
format ELF executable 3

segment readable executable

entry $

  xor  eax, eax
  push eax
  push 0x00000074
  push 0x6567772f ;/wget
  push 0x6e69622f
  push 0x7273752f ;/usr/bin
  mov  ebx, esp
  push eax
  push 0x00352f35
  push 0x2f666c6f ;olf/5/5
  push 0x672e7972
  push 0x616e6962 ;binary.g
  push 0x2f2f3a73
  push 0x70747468 ;https://
  mov  esi, esp
  push eax
  push esi
  push ebx
  mov  ecx, esp
  mov  al, 11        ;execve
  int  0x80          ;syscall
  mov  eax, 1
  int  0x80
