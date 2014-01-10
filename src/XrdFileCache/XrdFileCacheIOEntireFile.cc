//----------------------------------------------------------------------------------
// Copyright (c) 2014 by Board of Trustees of the Leland Stanford, Jr., University
// Author: Alja Mrak-Tadel, Matevz Tadel, Brian Bockelman
//----------------------------------------------------------------------------------
// XRootD is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// XRootD is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with XRootD.  If not, see <http://www.gnu.org/licenses/>.
//----------------------------------------------------------------------------------

#include <stdio.h>
#include <fcntl.h>
#include <utime.h>

#include "XrdClient/XrdClientConst.hh"
#include "XrdSys/XrdSysError.hh"
#include "XrdSfs/XrdSfsInterface.hh"
#include "XrdSys/XrdSysPthread.hh"
#include "XrdOss/XrdOss.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include <XrdSys/XrdSysPthread.hh>

#include "XrdFileCacheIOEntireFile.hh"
#include "XrdFileCacheLog.hh"
#include "XrdFileCacheFactory.hh"
#include "XrdFileCacheStats.hh"

using namespace XrdFileCache;

void *
PrefetchRunner(void * prefetch_void)
{
    XrdFileCache::Prefetch *prefetch = static_cast<XrdFileCache::Prefetch *>(prefetch_void);
    if (prefetch)
        prefetch->Run();
    return NULL;
}
//______________________________________________________________________________


IOEntireFile::IOEntireFile(XrdOucCacheIO &io, XrdOucCacheStats &stats, Cache & cache)
    : IO(io, stats, cache),
      m_prefetch(0)
{
    xfcMsgIO(kInfo, &m_io, "IO::IO() [%p]", this);

    std::string fname;
    m_cache.getFilePathFromURL(io.Path(), fname);

    m_prefetch = new Prefetch(io, fname, 0, io.FSize());
    pthread_t tid;
    XrdSysThread::Run(&tid, PrefetchRunner, (void *)(m_prefetch), 0, "XrdFileCache Prefetcher");

}

IOEntireFile::~IOEntireFile()
{}

XrdOucCacheIO *
IOEntireFile::Detach()
{
    m_statsGlobal.Add(m_prefetch->GetStats());

    XrdOucCacheIO * io = &m_io;

    delete m_prefetch;
    m_prefetch = 0;

    // This will delete us!
    m_cache.Detach(this);
    return io;
}

int
IOEntireFile::Read (char *buff, long long off, int size)
{
    xfcMsgIO(kDebug, &m_io, "IO::Read() [%p]  %lld@%d", this, off, size);

    ssize_t bytes_read = 0;
    ssize_t retval = 0;

    retval = m_prefetch->Read(buff, off, size);
    xfcMsgIO(kDebug, &m_io, "IO::Read() read from prefetch retval =  %d", retval);
    if (retval > 0)
    {

        bytes_read += retval;
        buff += retval;
        size -= retval;
    }


    if ((size > 0))
    {
        xfcMsgIO(kDebug, &m_io, "IO::Read() missed %d bytes", size);
        if (retval > 0) bytes_read += retval;
    }

    if (retval < 0)
    {
        xfcMsgIO(kError, &m_io, "IO::Read(), origin bytes read %d", retval);
    }

    return (retval < 0) ? retval : bytes_read;
}



/*
 * Perform a readv from the cache
 */
int
IOEntireFile::ReadV (const XrdOucIOVec *readV, int n)
{
    xfcMsgIO(kWarning, &m_io, "IO::ReadV(), get %d requests", n);

    ssize_t bytes_read = 0;
    size_t missing = 0;
    for (int i=0; i<n; i++)
    {
        XrdSfsXferSize size = readV[i].size;
        char * buff = readV[i].data;
        XrdSfsFileOffset off = readV[i].offset;
        if (m_prefetch)
        {
            ssize_t retval = Read(buff, off, size);
            if ((retval > 0) && (retval == size))
            {
                // TODO: could handle partial reads here
                bytes_read += size;
                continue;
            }
        }
        if (missing >= READV_MAXCHUNKS)
        {
            // Something went wrong in construction of this request;
            // Should be limited in higher layers to a max of 512 chunks.
            xfcMsgIO(kError, &m_io, "IO::ReadV(), missing %d >  READV_MAXCHUNKS %d",
                   missing,  READV_MAXCHUNKS);
            return -1;
        }
        missing++;
    }

    return bytes_read;
}
