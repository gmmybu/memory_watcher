////////////////////////////////////////////////////////////////////////////////
//  $Id: dbghelpapi.cpp,v 1.3 2006/11/12 18:09:19 dmouldin Exp $
//
//  Visual Leak Detector (Version 1.9d) - Global DbgHelp API Function Pointers
//  Copyright (c) 2006 Dan Moulding
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

#include "dbghelpapi.h"

// Global function pointers for explicit dynamic linking with the Debug Help
// Library APIs. Though these functions coule be load-time linked, we do an
// explicit dynmaic link to ensure that we link with the version of the library
// that was installed by VLD.
EnumerateLoadedModulesW64_t    pEnumerateLoadedModulesW64;
ImageDirectoryEntryToDataEx_t  pImageDirectoryEntryToDataEx;
StackWalk64_t                  pStackWalk64;
SymCleanup_t                   pSymCleanup;
SymFromAddrW_t                 pSymFromAddrW;
SymFunctionTableAccess64_t     pSymFunctionTableAccess64;
SymGetLineFromAddrW64_t        pSymGetLineFromAddrW64;
SymGetModuleBase64_t           pSymGetModuleBase64;
SymGetModuleInfoW64_t          pSymGetModuleInfoW64;
SymInitializeW_t               pSymInitializeW;
SymLoadModule64_t              pSymLoadModule64;
SymSetOptions_t                pSymSetOptions;
SymUnloadModule64_t            pSymUnloadModule64;

BOOL link_debughelp_library()
{
    size_t  count;
    WCHAR   dbghelppath[MAX_PATH] = { 0 };
    LPCSTR  functionname;
    wchar_t functionnamew[256];
    DWORD   length = MAX_PATH;
    HKEY    productkey;
    LONG    regstatus;
    DWORD   valuetype;

    if (wcslen(dbghelppath) == 0) {
        // Couldn't read the BinPath value, or it doesn't exist. Let the OS
        // search for dbghelp.dll, hopefully it will find a compatible version.
        wcsncpy_s(dbghelppath, MAX_PATH, L"dbghelp.dll", _TRUNCATE);
    }

    // Load the copy of dbghelp.dll installed by Visual Leak Detector.
    HMODULE m_dbghelp = LoadLibrary(dbghelppath);
    if (m_dbghelp == NULL)
        return FALSE;

    // Obtain pointers to the exported functions that we will be using.
    functionname = "EnumerateLoadedModulesW64";
    if ((pEnumerateLoadedModulesW64 = (EnumerateLoadedModulesW64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "ImageDirectoryEntryToDataEx";
    if ((pImageDirectoryEntryToDataEx = (ImageDirectoryEntryToDataEx_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "StackWalk64";
    if ((pStackWalk64 = (StackWalk64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymCleanup";
    if ((pSymCleanup = (SymCleanup_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymFromAddrW";
    if ((pSymFromAddrW = (SymFromAddrW_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymFunctionTableAccess64";
    if ((pSymFunctionTableAccess64 = (SymFunctionTableAccess64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymGetLineFromAddrW64";
    if ((pSymGetLineFromAddrW64 = (SymGetLineFromAddrW64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymGetModuleBase64";
    if ((pSymGetModuleBase64 = (SymGetModuleBase64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymInitializeW";
    if ((pSymInitializeW = (SymInitializeW_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymLoadModule64";
    if ((pSymLoadModule64 = (SymLoadModule64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymGetModuleInfoW64";
    if ((pSymGetModuleInfoW64 = (SymGetModuleInfoW64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymSetOptions";
    if ((pSymSetOptions = (SymSetOptions_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    functionname = "SymUnloadModule64";
    if ((pSymUnloadModule64 = (SymUnloadModule64_t)GetProcAddress(m_dbghelp, functionname)) == NULL) {
        return FALSE;
    }

    return TRUE;
}
