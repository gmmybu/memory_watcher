////////////////////////////////////////////////////////////////////////////////
//  $Id: callstack.h,v 1.8 2006/11/12 18:09:19 dmouldin Exp $
//
//  Visual Leak Detector (Version 1.9d) - CallStack Class Definitions
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

#pragma once

#include <windows.h>

#define CALLSTACKCHUNKSIZE 16 // Number of frame slots in each CallStack chunk.

////////////////////////////////////////////////////////////////////////////////
//
//  The CallStack Class
//
//    CallStack objects can be used for obtaining, storing, and displaying the
//    call stack at a given point during program execution.
//
//    The primary data structure used by the CallStack is similar in concept to
//    a STL vector, but is specifically tailored for use by VLD, making it more
//    efficient than a standard STL vector.
//
//    Inside the CallStack are a number of "chunks" which are arranged in a
//    linked list. Each chunk contains an array of frames (each frame is
//    represented by a program counter address). If we run out of space when
//    pushing new frames onto an existing chunk in the CallStack chunk list,
//    then a new chunk is allocated and appended to the end of the list. In this
//    way, the CallStack can grow dynamically as needed. New frames are always
//    pushed onto the chunk at the end of the list known as the "top" chunk.
//
class CallStack
{
public:
    CallStack ();
    ~CallStack ();

    // Public APIs - see each function definition for details.
    VOID clear ();
    VOID dump (BOOL showinternalframes) const;
    virtual VOID getstacktrace (UINT32 maxdepth, SIZE_T *framepointer) = 0;
    SIZE_T operator [] (UINT32 index) const;
    VOID push_back (const SIZE_T programcounter);
protected:
    SIZE_T m_frames[CALLSTACKCHUNKSIZE];
    UINT32 m_size;     // Current size (in frames)

    CallStack(const CallStack&);
    CallStack& operator=(const CallStack&);
};

////////////////////////////////////////////////////////////////////////////////
//
//  The FastCallStack Class
//
//    This class is a specialization of the CallStack class which provides a
//    very fast stack tracing function.
//
class FastCallStack : public CallStack
{
public:
    VOID getstacktrace (UINT32 maxdepth, SIZE_T *framepointer);
};

////////////////////////////////////////////////////////////////////////////////
//
//  The SafeCallStack Class
//
//    This class is a specialization of the CallStack class which provides a
//    more robust, but quite slow, stack tracing function.
//
class SafeCallStack : public CallStack
{
public:
    VOID getstacktrace (UINT32 maxdepth, SIZE_T *framepointer);
};