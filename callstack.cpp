////////////////////////////////////////////////////////////////////////////////
//  $Id: callstack.cpp,v 1.16 2006/11/12 18:09:19 dmouldin Exp $
//
//  Visual Leak Detector (Version 1.9d) - CallStack Class Implementations
//  Copyright (c) 2005-2006 Dan Moulding
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  See COPYING.txt for the full terms of the GNU Lesser General Public License.
//
////////////////////////////////////////////////////////////////////////////////

#include <cassert>
#include <windows.h>
#include <stdio.h>
#include "callstack.h"  // This class' header.
#include "dbghelpapi.h" // Provides symbol handling services.

#define MAXSYMBOLNAMELENGTH 256

// Imported global variables.
#define currentprocess GetCurrentProcess()
#define currentthread  GetCurrentThread()

#define ADDRESSFORMAT L"0x%.8X"  // Format string for 32-bit addresses
#define SIZEOFPTR 4
#define X86X64ARCHITECTURE IMAGE_FILE_MACHINE_I386
#define AXREG Eax
#define BPREG Ebp
#define IPREG Eip
#define SPREG Esp

#define FRAMEPOINTER(fp) __asm mov fp, BPREG // Copies the current frame pointer to the supplied variable.

#define MAXREPORTLENGTH 511 

VOID report(LPCWSTR format, ...)
{
    va_list args;
    size_t  count;
    CHAR    messagea[MAXREPORTLENGTH + 1];
    WCHAR   messagew[MAXREPORTLENGTH + 1];

    va_start(args, format);
    _vsnwprintf_s(messagew, MAXREPORTLENGTH + 1, _TRUNCATE, format, args);
    va_end(args);
    messagew[MAXREPORTLENGTH] = L'\0';

    OutputDebugStringW(messagew);
    Sleep(10);
}

// Constructor - Initializes the CallStack with an initial size of zero and one
//   Chunk of capacity.
//
CallStack::CallStack ()
{
    m_size = 0;
}

// Destructor - Frees all memory allocated to the CallStack.
//
CallStack::~CallStack ()
{
}

// operator [] - Random access operator. Retrieves the frame at the specified
//   index.
//
//   Note: We give up a bit of efficiency here, in favor of efficiency of push
//     operations. This is because walking of a CallStack is done infrequently
//     (only if a leak is found), whereas pushing is done very frequently (for
//     each frame in the program's call stack when the program allocates some
//     memory).
//
//  - index (IN): Specifies the index of the frame to retrieve.
//
//  Return Value:
//
//    Returns the program counter for the frame at the specified index. If the
//    specified index is out of range for the CallStack, the return value is
//    undefined.
//
SIZE_T CallStack::operator [] (UINT32 index) const
{
    return m_frames[index % CALLSTACKCHUNKSIZE];
}

// clear - Resets the CallStack, returning it to a state where no frames have
//   been pushed onto it, readying it for reuse.
//
//   Note: Calling this function does not release any memory allocated to the
//     CallStack. We give up a bit of memory-usage efficiency here in favor of
//     performance of push operations.
//
//  Return Value:
//
//    None.
//
VOID CallStack::clear ()
{
    m_size = 0;
}

// dump - Dumps a nicely formatted rendition of the CallStack, including
//   symbolic information (function names and line numbers) if available.
//
//   Note: The symbol handler must be initialized prior to calling this
//     function.
//
//   Caution: This function is not thread-safe. It calls into the Debug Help
//     Library which is single-threaded. Therefore, calls to this function must
//     be synchronized.
//
//  - showinternalframes (IN): If true, then all frames in the CallStack will be
//      dumped. Otherwise, frames internal to the heap will not be dumped.
//
//  Return Value:
//
//    None.
//
VOID CallStack::dump(BOOL showinternalframes) const
{
    DWORD            displacement;
    DWORD64          displacement64;
    BOOL             foundline;
    UINT32           frame;
    SYMBOL_INFO     *functioninfo;
    LPWSTR           functionname;
    SIZE_T           programcounter;
    IMAGEHLP_LINE64  sourceinfo = { 0 };
    BYTE             symbolbuffer [sizeof(SYMBOL_INFO) + (MAXSYMBOLNAMELENGTH * sizeof(WCHAR)) - 1] = { 0 };

    // Initialize structures passed to the symbol handler.
    functioninfo = (SYMBOL_INFO*)&symbolbuffer;
    functioninfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    functioninfo->MaxNameLen = MAXSYMBOLNAMELENGTH;
    sourceinfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    // Iterate through each frame in the call stack.
    OutputDebugStringW(L"\n");
    for (frame = 0; frame < m_size; frame++) {
        // Try to get the source file and line number associated with
        // this program counter address.
        programcounter = (*this)[frame];
        if ((foundline = pSymGetLineFromAddrW64(currentprocess, programcounter, &displacement, &sourceinfo)) == TRUE) {
            if (!showinternalframes) {
                _wcslwr_s(sourceinfo.FileName, wcslen(sourceinfo.FileName) + 1);
                if (wcsstr(sourceinfo.FileName, L"afxmem.cpp") ||
                    wcsstr(sourceinfo.FileName, L"dbgheap.c") ||
                    wcsstr(sourceinfo.FileName, L"malloc.c") ||
                    wcsstr(sourceinfo.FileName, L"new.cpp") ||
                    wcsstr(sourceinfo.FileName, L"newaop.cpp")) {
                    // Don't show frames in files internal to the heap.
                    continue;
                }
            }
        }

        // Try to get the name of the function containing this program
        // counter address.
        if (pSymFromAddrW(currentprocess, (*this)[frame], &displacement64, functioninfo)) {
            functionname = functioninfo->Name;
        }
        else {
            functionname = L"(Function name unavailable)";
        }

        // Display the current stack frame's information.
        if (foundline) {
            report(L"    %s (%d): %s\n", sourceinfo.FileName, sourceinfo.LineNumber, functionname);
        }
        else {
            report(L"    " ADDRESSFORMAT L" (File and line number not available): ", (*this)[frame]);
            report(L"%s\n", functionname);
        }
    }
    OutputDebugStringW(L"\n");
}

// push_back - Pushes a frame's program counter onto the CallStack. Pushes are
//   always appended to the back of the chunk list (aka the "top" chunk).
//
//   Note: This function will allocate additional memory as necessary to make
//     room for new program counter addresses.
//
//  - programcounter (IN): The program counter address of the frame to be pushed
//      onto the CallStack.
//
//  Return Value:
//
//    None.
//
VOID CallStack::push_back(const SIZE_T programcounter)
{
    if (m_size < CALLSTACKCHUNKSIZE) {
        m_frames[m_size++] = programcounter;
    }
}

// getstacktrace - Traces the stack as far back as possible, or until 'maxdepth'
//   frames have been traced. Populates the CallStack with one entry for each
//   stack frame traced.
//
//   Note: This function uses a very efficient method to walk the stack from
//     frame to frame, so it is quite fast. However, unconventional stack frames
//     (such as those created when frame pointer omission optimization is used)
//     will not be successfully walked by this function and will cause the
//     stack trace to terminate prematurely.
//
//  - maxdepth (IN): Maximum number of frames to trace back.
//
//  - framepointer (IN): Frame (base) pointer at which to begin the stack trace.
//      If NULL, then the stack trace will begin at this function.
//
//  Return Value:
//
//    None.
//
VOID FastCallStack::getstacktrace (UINT32 maxdepth, SIZE_T *framepointer)
{
    UINT32  count = 0;

    if (framepointer == NULL) {
        // Begin the stack trace with the current frame. Obtain the current
        // frame pointer.
        FRAMEPOINTER(framepointer);
    }

    while (count < maxdepth) {
        if ((SIZE_T*)*framepointer < framepointer) {
            if ((SIZE_T*)*framepointer == NULL) {
                // Looks like we reached the end of the stack.
                break;
            }
            else {
                // Invalid frame pointer. Frame pointer addresses should always
                // increase as we move up the stack.
                m_size = 0;
                break;
            }
        }
        if ((SIZE_T)*framepointer & (sizeof(SIZE_T*) - 1)) {
            // Invalid frame pointer. Frame pointer addresses should always
            // be aligned to the size of a pointer. This probably means that
            // we've encountered a frame that was created by a module built with
            // frame pointer omission (FPO) optimization turned on.
            m_size = 0;
            break;
        }
        if (IsBadReadPtr((SIZE_T*)*framepointer, sizeof(SIZE_T*))) {
            // Bogus frame pointer. Again, this probably means that we've
            // encountered a frame built with FPO optimization.
            m_size = 0;
            break;
        }
        count++;
        push_back(*(framepointer + 1));
        framepointer = (SIZE_T*)*framepointer;
    }
}

// getstacktrace - Traces the stack as far back as possible, or until 'maxdepth'
//   frames have been traced. Populates the CallStack with one entry for each
//   stack frame traced.
//
//   Note: This function uses a documented Windows API to walk the stack. This
//     API is supposed to be the most reliable way to walk the stack. It claims
//     to be able to walk stack frames that do not follow the conventional stack
//     frame layout. However, this robustness comes at a cost: it is *extremely*
//     slow compared to walking frames by following frame (base) pointers.
//
//  - maxdepth (IN): Maximum number of frames to trace back.
//
//  - framepointer (IN): Frame (base) pointer at which to begin the stack trace.
//      If NULL, then the stack trace will begin at this function.
//
//  Return Value:
//
//    None.
//
VOID SafeCallStack::getstacktrace (UINT32 maxdepth, SIZE_T *framepointer)
{
    DWORD        architecture;
    CONTEXT      context;
    UINT32       count = 0;
    STACKFRAME64 frame;
    SIZE_T       programcounter;
    SIZE_T       stackpointer;

    if (framepointer == NULL) {
        // Begin the stack trace with the current frame. Obtain the current
        // frame pointer.
        FRAMEPOINTER(framepointer);
    }

    // Get the required values for initialization of the STACKFRAME64 structure
    // to be passed to StackWalk64(). Required fields are AddrPC and AddrFrame.
#if defined(_M_IX86) || defined(_M_X64)
    architecture   = X86X64ARCHITECTURE;
    programcounter = *(framepointer + 1);
    stackpointer   = *framepointer;  // An approximation.
    context.BPREG  = *framepointer;
    context.IPREG  = programcounter;
    context.SPREG  = stackpointer;
#else
// If you want to retarget Visual Leak Detector to another processor
// architecture then you'll need to provide architecture-specific code to
// obtain the program counter and stack pointer from the given frame pointer.
#error "Visual Leak Detector is not supported on this architecture."
#endif // _M_IX86 || _M_X64

    // Initialize the STACKFRAME64 structure.
    memset(&frame, 0x0, sizeof(frame));
    frame.AddrFrame.Offset = *framepointer;
    frame.AddrFrame.Mode   = AddrModeFlat;
    frame.AddrPC.Offset    = programcounter;
    frame.AddrPC.Mode      = AddrModeFlat;
    frame.AddrStack.Offset = stackpointer;
    frame.AddrStack.Mode   = AddrModeFlat;

    // Walk the stack.
    while (count < maxdepth) {
        count++;
        if (!pStackWalk64(architecture, currentprocess, currentthread, &frame, &context, NULL,
                          pSymFunctionTableAccess64, pSymGetModuleBase64, NULL)) {
            // Couldn't trace back through any more frames.
            break;
        }
        if (frame.AddrFrame.Offset == 0) {
            // End of stack.
            break;
        }

        // Push this frame's program counter onto the CallStack.
        push_back((SIZE_T)frame.AddrPC.Offset);
    }
}
