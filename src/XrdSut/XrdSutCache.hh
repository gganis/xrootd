#ifndef  __SUT_CACHE_H
#define  __SUT_CACHE_H
/******************************************************************************/
/*                                                                            */
/*                       X r d S u t C a c h e . h h                          */
/*                                                                            */
/* (c) 2005 by the Board of Trustees of the Leland Stanford, Jr., University  */
/*   Produced by Gerri Ganis for CERN                                         */
/*                                                                            */
/* This file is part of the XRootD software suite.                            */
/*                                                                            */
/* XRootD is free software: you can redistribute it and/or modify it under    */
/* the terms of the GNU Lesser General Public License as published by the     */
/* Free Software Foundation, either version 3 of the License, or (at your     */
/* option) any later version.                                                 */
/*                                                                            */
/* XRootD is distributed in the hope that it will be useful, but WITHOUT      */
/* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or      */
/* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public       */
/* License for more details.                                                  */
/*                                                                            */
/* You should have received a copy of the GNU Lesser General Public License   */
/* along with XRootD in a file called COPYING.LESSER (LGPL license) and file  */
/* COPYING (GPL license).  If not, see <http://www.gnu.org/licenses/>.        */
/*                                                                            */
/* The copyright holder's institutional names and contributor's names may not */
/* be used to endorse or promote products derived from this software without  */
/* specific prior written permission of the institution or contributor.       */
/******************************************************************************/

#include "XrdOuc/XrdOucHash.hh"
#include "XrdSut/XrdSutCacheEntry.hh"
#include "XrdSys/XrdSysPthread.hh"

/******************************************************************************/
/*                                                                            */
/*  Class defining the basic memory cache                                     */
/*                                                                            */
/******************************************************************************/

typedef bool (*XrdSutCacheGet_t)(XrdSutCacheEntry *, void *);
typedef struct {
   long arg1;
   long arg2;
   long arg3;
   long arg4;
} XrdSutCacheArg_t;

class XrdSutCache {
public:
   XrdSutCache(int psize = 89, int size = 144, int load = 80) : table(psize, size, load) {}
   virtual ~XrdSutCache() {}


   XrdSutCacheEntry *Get(const char *tag, bool &rdlock, XrdSutCacheGet_t condition = 0, void *arg = 0) {
      // Get or create the entry with 'tag'.
      // New entries are always returned write-locked.
      // The status of existing ones depends on condition: if condition is undefined or if applied
      // to the entry with arguments 'arg' returns true, the entry is returned read-locked.
      // Otherwise a write-lock is attempted on the entry: if unsuccessful (another thread is modifing
      // the entry) the entry is read-locked.
      // The status of the lock is returned in rdlock (true if read-locked).
      rdlock = false;
      bool oldentry = true;
      XrdSutCacheEntry *cent = 0;
      {  XrdSysMutexHelper raii(mtx);
         if (!(cent = table.Find(tag))) {
            cent = new XrdSutCacheEntry(tag);
            table.Add(tag, cent);
            cent->rwmtx.WriteLock();
            oldentry = false;
         }
      }
      if (oldentry) {
        if (condition) {
           if ((*condition)(cent, arg)) {
              cent->rwmtx.ReadLock();
              rdlock = true;
           } else {
              if (!(cent->rwmtx.CondWriteLock())) {
                 cent->rwmtx.ReadLock();
                 // Another thread has modified the entry
                 if ((*condition)(cent, arg)) {
                    rdlock = true;
                 } else {
                    // The entry is still bad: we fail
                    cent->rwmtx.UnLock();
                    return (XrdSutCacheEntry *)0;
                 }
              }
           }
        } else {
           cent->rwmtx.ReadLock();
           rdlock = true;
        }
      }
      return cent;
   }

   inline int Size() { return table.Num(); }
   inline void Reset() { return table.Purge(); }

private:
   XrdSysRecMutex         mtx;  // Protect access to table
   XrdOucHash<XrdSutCacheEntry> table; // table with content
};

#endif
