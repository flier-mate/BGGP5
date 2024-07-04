;BGGP5 - Jun 23, 2024
;@fliermate
;
; Revision 2 - 596 bytes (July 4, 2024)
;
;Compile with FASM2
;
;Noticeable changes are:
;-FileAlignment set to 4 instead of 512
;-SectionAlignment set to 4 instead of 4096
;-DataDirectory size kept to 2 instead of 16
;
;The remaining header fields are kept unmodified as in original BASIC.ASM (PE template by Tomasz Grysztar)
;
;Thank you to @netspooky and their team for the wonderful BGGP!

format binary as "exe"

macro align? pow2*,value:?
        db  (-$) and (pow2-1)  dup value
end macro

;include '80386.inc'
use32

IMAGE_BASE := 0x400000
org IMAGE_BASE

FILE_ALIGNMENT := 4
SECTION_ALIGNMENT := 4

Stub:
        .Signature                      dw "MZ"
        ;.BytesInLastSector              dw SIZE_OF_STUB mod 512
        ;.NumberOfSectors                dw (SIZE_OF_STUB-1)/512 + 1
        ;.NumberOfRelocations            dw 0
        ;.NumberOfHeaderParagraphs       dw SIZE_OF_STUB_HEADER / 16
        ;                                db 0x3C - ($-Stub) dup 0
align 4
        ;.NewHeaderOffset                dd Header-IMAGE_BASE

;align 16

;SIZE_OF_STUB_HEADER := $ - Stub

        ; The code of a DOS program would go here.

;SIZE_OF_STUB := $ - Stub

;align 8

Header:
        .Signature                      dw "PE",0
        .Machine                        dw 0x14C ; IMAGE_FILE_MACHINE_I386
        .NumberOfSections               dw NUMBER_OF_SECTIONS
        .TimeDateStamp                  dd %t
        .PointerToSymbolTable           dd 0
        .NumberOfSymbols                dd 0
        .SizeOfOptionalHeader           dw SectionTable - OptionalHeader
        .Characteristics                dw 0x102 ; IMAGE_FILE_32BIT_MACHINE + IMAGE_FILE_EXECUTABLE_IMAGE

OptionalHeader:
        .Magic                          dw 0x10B
        .MajorLinkerVersion             db 0
        .MinorLinkerVersion             db 0
        .SizeOfCode                     dd 0
        .SizeOfInitializedData          dd 0
        .SizeOfUninitializedData        dd 0
        .AddressOfEntryPoint            dd EntryPoint-IMAGE_BASE
        .BaseOfCode                     dd 0
        .BaseOfData                     dd 0
        .ImageBase                      dd IMAGE_BASE
        .SectionAlignment               dd SECTION_ALIGNMENT
        .FileAlignment                  dd FILE_ALIGNMENT
        .MajorOperatingSystemVersion    dw 3
        .MinorOperatingSystemVersion    dw 10
        .MajorImageVersion              dw 0
        .MinorImageVersion              dw 0
        .MajorSubsystemVersion          dw 3
        .MinorSubsystemVersion          dw 10
        .Win32VersionValue              dd 0
        .SizeOfImage                    dd SIZE_OF_IMAGE
        .SizeOfHeaders                  dd SIZE_OF_HEADERS
        .CheckSum                       dd 0
        .Subsystem                      dw 2 ; IMAGE_SUBSYSTEM_WINDOWS_GUI
        .DllCharacteristics             dw 0
        .SizeOfStackReserve             dd 4096
        .SizeOfStackCommit              dd 4096
        .SizeOfHeapReserve              dd 65536
        .SizeOfHeapCommit               dd 0
        .LoaderFlags                    dd 0
        .NumberOfRvaAndSizes            dd NUMBER_OF_RVA_AND_SIZES

RvaAndSizes:
        .Export.Rva                     dd 0
        .Export.Size                    dd 0
        .Import.Rva                     dd ImportTable-IMAGE_BASE
        .Import.Size                    dd ImportTable.End-ImportTable
        ;.Resource.Rva                   dd 0
        ;.Resource.Size                  dd 0
        ;.Exception.Rva                  dd 0
        ;.Exception.Size                 dd 0
        ;.Certificate.Rva                dd 0
        ;.Certificate.Size               dd 0
        ;.BaseRelocation.Rva             dd 0
        ;.BaseRelocation.Size            dd 0
        ;.Debug.Rva                      dd 0
        ;.Debug.Size                     dd 0
        ;.Architecture.Rva               dd 0
        ;.Architecture.Size              dd 0
        ;.GlobalPtr.Rva                  dd 0
        ;.GlobalPtr.Size                 dd 0
        ;.TLS.Rva                        dd 0
        ;.TLS.Size                       dd 0
        ;.LoadConfig.Rva                 dd 0
        ;.LoadConfig.Size                dd 0
        ;.BoundImport.Rva                dd 0
        ;.BoundImport.Size               dd 0
        ;.IAT.Rva                        dd 0
        ;.IAT.Size                       dd 0
        ;.DelayImport.Rva                dd 0
        ;.DelayImport.Size               dd 0
        ;.COMPlus.Rva                    dd 0
        ;.COMPlus.Size                   dd 0
        ;.Reserved.Rva                   dd 0
        ;.Reserved.Size                  dd 0

SectionTable:

        .1.Name                         dq +'.text'
        .1.VirtualSize                  dd Section.1.End - Section.1
        .1.VirtualAddress               dd Section.1 - IMAGE_BASE
        .1.SizeOfRawData                dd Section.1.SIZE_IN_FILE
        .1.PointerToRawData             dd Section.1.OFFSET_IN_FILE
        .1.PointerToRelocations         dd 0
        .1.PointerToLineNumbers         dd 0
        .1.NumberOfRelocations          dw 0
        .1.NumberOfLineNumbers          dw 0
        .1.Characteristics              dd 0x60000000 ; IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_READ

        .2.Name                         dq +'.rdata'
        .2.VirtualSize                  dd Section.2.End - Section.2
        .2.VirtualAddress               dd Section.2 - IMAGE_BASE
        .2.SizeOfRawData                dd Section.2.SIZE_IN_FILE
        .2.PointerToRawData             dd Section.2.OFFSET_IN_FILE
        .2.PointerToRelocations         dd 0
        .2.PointerToLineNumbers         dd 0
        .2.NumberOfRelocations          dw 0
        .2.NumberOfLineNumbers          dw 0
        .2.Characteristics              dd 0xC0000000 ; IMAGE_SCN_MEM_READ + IMAGE_SCN_MEM_WRITE

SectionTable.End:

NUMBER_OF_RVA_AND_SIZES := (SectionTable-RvaAndSizes)/8
NUMBER_OF_SECTIONS := (SectionTable.End-SectionTable)/40
SIZE_OF_HEADERS := Section.1.OFFSET_IN_FILE

align SECTION_ALIGNMENT
Section.1:

section $%%
align FILE_ALIGNMENT,0
Section.1.OFFSET_IN_FILE:

section Section.1

        EntryPoint:

        mov     ebp, esp
        sub     esp, 64
        push    0
        push    0
        push    _file
        push    _url
        push    0
        call    [URLDownloadToFileA]

        push    0
        push    080h          ;FILE_ATTRIBUTE_NORMAL
        push    3             ;OPEN_EXISTING
        push    0
        push    00000001h     ;FILE_SHARE_READ
        push    80000000h     ;GENERIC_READ
        push    _file
        call    [CreateFileA]
        ;mov     dword [_in], eax

        push    0
        push    0         ;_read
        push    58
        push    ebp       ;_buffer
        push    eax       ;[_in]
        call    [ReadFile]

        ;push    [_in]
        ;call    [CloseHandle]

        push    0x40
        push    _file
        push    ebp       ;_buffer
        push    0
        call    [MessageBoxA]

        push    5
        call    [ExitProcess]

Section.1.End:

align SECTION_ALIGNMENT
Section.2:

section $%%
align FILE_ALIGNMENT,0
Section.1.SIZE_IN_FILE := $ - Section.1.OFFSET_IN_FILE
Section.2.OFFSET_IN_FILE:

section Section.2

        ImportTable:
 
                .1.ImportLookupTableRva         dd KernelLookupTable-IMAGE_BASE
                .1.TimeDateStamp                dd 0
                .1.ForwarderChain               dd 0
                .1.NameRva                      dd KernelDLLName-IMAGE_BASE
                .1.ImportAddressTableRva        dd KernelAddressTable-IMAGE_BASE
 
                .2.ImportLookupTableRva         dd UrlMonLookupTable-IMAGE_BASE
                .2.TimeDateStamp                dd 0
                .2.ForwarderChain               dd 0
                .2.NameRva                      dd UrlMonDLLName-IMAGE_BASE
                .2.ImportAddressTableRva        dd UrlMonAddressTable-IMAGE_BASE
 
                .3.ImportLookupTableRva         dd UserLookupTable-IMAGE_BASE
                .3.TimeDateStamp                dd 0
                .3.ForwarderChain               dd 0
                .3.NameRva                      dd UserDLLName-IMAGE_BASE
                .3.ImportAddressTableRva        dd UserAddressTable-IMAGE_BASE

                                                dd 0,0,0,0,0

                KernelLookupTable:
                                dd ExitProcessLookup-IMAGE_BASE
                                dd CreateFileALookup-IMAGE_BASE
                                dd ReadFileLookup-IMAGE_BASE
                                ;dd CloseHandleLookup-IMAGE_BASE
                                dd 0

                KernelAddressTable:
                ExitProcess     dd ExitProcessLookup-IMAGE_BASE ; this is going to be replaced with the address of the function
                CreateFileA     dd CreateFileALookup-IMAGE_BASE ; this is going to be replaced with the address of the function
                ReadFile        dd ReadFileLookup-IMAGE_BASE ; this is going to be replaced with the address of the function
                ;CloseHandle     dd CloseHandleLookup-IMAGE_BASE ; this is going to be replaced with the address of the function
                                dd 0
 
                UrlMonLookupTable:
                                dd URLDownloadToFileALookup-IMAGE_BASE
                                dd 0

                UrlMonAddressTable:
                URLDownloadToFileA  dd URLDownloadToFileALookup-IMAGE_BASE ; this is going to be replaced with the address of the function
                                    dd 0
 
                UserLookupTable:
                                dd MessageBoxALookup-IMAGE_BASE
                                dd 0

                UserAddressTable:
                MessageBoxA     dd MessageBoxALookup-IMAGE_BASE ; this is going to be replaced with the address of the function
                                    dd 0

                                align 2

                ExitProcessLookup:
                        .Hint   dw 0
                        .Name   db 'ExitProcess',0
                                align 2

                CreateFileALookup:
                        .Hint   dw 0
                        .Name   db 'CreateFileA',0
                                align 2

                ReadFileLookup:
                        .Hint   dw 0
                        .Name   db 'ReadFile',0
                                align 2

                ;CloseHandleLookup:
                ;        .Hint   dw 0
                ;        .Name   db 'CloseHandle',0
                ;                align 2

                URLDownloadToFileALookup:
                        .Hint   dw 0
                        .Name   db 'URLDownloadToFileA',0
                                align 2

                MessageBoxALookup:
                        .Hint   dw 0
                        .Name   db 'MessageBoxA',0
                                align 2

                KernelDLLName   db 'KERNEL32.DLL',0
                UrlMonDLLName   db 'URLMON.DLL',0
                UserDLLName     db 'USER32.DLL',0
 
        ImportTable.End:

        ;_buffer  rb 58
        ;         db 0
        ;_read    dd ?
        ;_in      dd ?
        _url     db 'https://binary.golf/5/'  ;Special trick by @bitshifter
        _file    db '5',0

Section.2.End:

align SECTION_ALIGNMENT
SIZE_OF_IMAGE := $ - IMAGE_BASE

section $%%
align FILE_ALIGNMENT,0
Section.2.SIZE_IN_FILE := $ - Section.2.OFFSET_IN_FILE