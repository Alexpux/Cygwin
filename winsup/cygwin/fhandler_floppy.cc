/* fhandler_floppy.cc.  See fhandler.h for a description of the
   fhandler classes.

   Copyright 1999, 2000, 2001, 2002 Red Hat, Inc.

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include "winsup.h"
#include <sys/termios.h>
#include <errno.h>
#include <unistd.h>
#include <winioctl.h>
#include <asm/socket.h>
#include <cygwin/hdreg.h>
#include <cygwin/fs.h>
#include "security.h"
#include "fhandler.h"
#include "cygerrno.h"

/**********************************************************************/
/* fhandler_dev_floppy */

int
fhandler_dev_floppy::is_eom (int win_error)
{
  int ret = (win_error == ERROR_INVALID_PARAMETER);
  if (ret)
    debug_printf ("end of medium");
  return ret;
}

int
fhandler_dev_floppy::is_eof (int)
{
  int ret = 0;
  if (ret)
    debug_printf ("end of file");
  return ret;
}

fhandler_dev_floppy::fhandler_dev_floppy (int unit) : fhandler_dev_raw (FH_FLOPPY, unit)
{
}

int
fhandler_dev_floppy::open (path_conv *real_path, int flags, mode_t)
{
  /* The correct size of the buffer would be 512 bytes,
   * which is the atomic size, supported by WinNT.
   * Unfortunately, the performance is worse than
   * access to file system on same device!
   * Setting buffer size to a relatively big value
   * increases performance by means.
   * The new ioctl call with 'rdevio.h' header file
   * supports changing this value.
   *
   * Let's be smart: Let's take a multiplier of typical tar
   * and cpio buffer sizes by default!
  */
  devbufsiz = 61440L; /* 512L; */
  return fhandler_dev_raw::open (real_path, flags);
}

int
fhandler_dev_floppy::close (void)
{
  int ret;

  ret = writebuf ();
  if (ret)
    {
      fhandler_dev_raw::close ();
      return ret;
    }
  return fhandler_dev_raw::close ();
}

_off64_t
fhandler_dev_floppy::lseek (_off64_t offset, int whence)
{
  int ret;
  char buf[512];
  _off64_t drive_size = 0;
  _off64_t lloffset = offset;
  _off64_t current_position;
  _off64_t sector_aligned_offset;
  _off64_t bytes_left;
  DWORD low;
  LONG high = 0;

  DISK_GEOMETRY di;
  PARTITION_INFORMATION pi;
  DWORD bytes_read;

  if (!DeviceIoControl (get_handle (),
			  IOCTL_DISK_GET_DRIVE_GEOMETRY,
			  NULL, 0,
			  &di, sizeof (di),
			  &bytes_read, NULL))
    {
      __seterrno ();
      return -1;
    }
  debug_printf ("disk geometry: (%ld cyl)*(%ld trk)*(%ld sec)*(%ld bps)",
		 di.Cylinders.LowPart,
		 di.TracksPerCylinder,
		 di.SectorsPerTrack,
		 di.BytesPerSector);
  if (DeviceIoControl (get_handle (),
			 IOCTL_DISK_GET_PARTITION_INFO,
			 NULL, 0,
			 &pi, sizeof (pi),
			 &bytes_read, NULL))
    {
      debug_printf ("partition info: %ld (%ld)",
		      pi.StartingOffset.LowPart,
		      pi.PartitionLength.LowPart);
      drive_size = pi.PartitionLength.QuadPart;
    }
  else
    {
      drive_size = di.Cylinders.QuadPart * di.TracksPerCylinder *
		   di.SectorsPerTrack * di.BytesPerSector;
    }
  debug_printf ("drive size: %ld", drive_size);

  if (whence == SEEK_END && drive_size > 0)
    {
      lloffset = offset + drive_size;
      whence = SEEK_SET;
    }

  if (whence == SEEK_CUR)
    {
      low = SetFilePointer (get_handle (), 0, &high, FILE_CURRENT);
      if (low == INVALID_SET_FILE_POINTER && GetLastError ())
	{
	  __seterrno ();
	  return -1;
	}
      current_position = low + ((_off64_t) high << 32);
      if (is_writing)
	current_position += devbufend - devbufstart;
      else
	current_position -= devbufend - devbufstart;

      lloffset += current_position;
      whence = SEEK_SET;
    }

  if (lloffset < 0 ||
      drive_size > 0 && lloffset > drive_size)
    {
      set_errno (EINVAL);
      return -1;
    }

  /* FIXME: sector can possibly be not 512 bytes long */
  sector_aligned_offset = (lloffset / 512) * 512;
  bytes_left = lloffset - sector_aligned_offset;

  if (whence == SEEK_SET)
    {
      /* Invalidate buffer. */
      ret = writebuf ();
      if (ret)
	return ret;
      devbufstart = devbufend = 0;

      low = sector_aligned_offset & 0xffffffff;
      high = sector_aligned_offset >> 32;
      if (SetFilePointer (get_handle (), low, &high, FILE_BEGIN)
	  == INVALID_SET_FILE_POINTER && GetLastError ())
	{
	  __seterrno ();
	  return -1;
	}

      size_t len = bytes_left;
      raw_read (buf, len);
      return sector_aligned_offset + bytes_left;
    }

  set_errno (EINVAL);
  return -1;
}

int
fhandler_dev_floppy::ioctl (unsigned int cmd, void *buf)
{
  DISK_GEOMETRY di;
  PARTITION_INFORMATION pi;
  DWORD bytes_read;
  _off64_t drive_size = 0;
  _off64_t start = 0;
  switch (cmd)
    {
    case HDIO_GETGEO:
      {
	debug_printf ("HDIO_GETGEO");
	if (!DeviceIoControl (get_handle (),
			      IOCTL_DISK_GET_DRIVE_GEOMETRY,
			      NULL, 0,
			      &di, sizeof (di),
			      &bytes_read, NULL))
	  {
	    __seterrno ();
	    return -1;
	  }
	debug_printf ("disk geometry: (%ld cyl)*(%ld trk)*(%ld sec)*(%ld bps)",
		      di.Cylinders.LowPart,
		      di.TracksPerCylinder,
		      di.SectorsPerTrack,
		      di.BytesPerSector);
	if (DeviceIoControl (get_handle (),
			     IOCTL_DISK_GET_PARTITION_INFO,
			     NULL, 0,
			     &pi, sizeof (pi),
			     &bytes_read, NULL))
	  {
	    debug_printf ("partition info: %ld (%ld)",
			  pi.StartingOffset.LowPart,
			  pi.PartitionLength.LowPart);
	    start = pi.StartingOffset.QuadPart >> 9ULL;
	  }
	struct hd_geometry *geo = (struct hd_geometry *) buf;
	geo->heads = di.TracksPerCylinder;
	geo->sectors = di.SectorsPerTrack;
	geo->cylinders = di.Cylinders.LowPart;
	geo->start = start;
	return 0;
      }
    case BLKGETSIZE:
    case BLKGETSIZE64:
      {
	debug_printf ("BLKGETSIZE");
	if (!DeviceIoControl (get_handle (),
			      IOCTL_DISK_GET_DRIVE_GEOMETRY,
			      NULL, 0,
			      &di, sizeof (di),
			      &bytes_read, NULL))
	  {
	    __seterrno ();
	    return -1;
	  }
	debug_printf ("disk geometry: (%ld cyl)*(%ld trk)*(%ld sec)*(%ld bps)",
		      di.Cylinders.LowPart,
		      di.TracksPerCylinder,
		      di.SectorsPerTrack,
		      di.BytesPerSector);
	if (DeviceIoControl (get_handle (),
			     IOCTL_DISK_GET_PARTITION_INFO,
			     NULL, 0,
			     &pi, sizeof (pi),
			     &bytes_read, NULL))
	  {
	    debug_printf ("partition info: %ld (%ld)",
			  pi.StartingOffset.LowPart,
			  pi.PartitionLength.LowPart);
	    drive_size = pi.PartitionLength.QuadPart;
	  }
	else
	  {
	    drive_size = di.Cylinders.QuadPart * di.TracksPerCylinder *
			 di.SectorsPerTrack * di.BytesPerSector;
	  }
	if (cmd == BLKGETSIZE)
	  *(long *)buf = drive_size >> 9UL;
	else
	  *(_off64_t *)buf = drive_size;
	return 0;
      }
    case BLKRRPART:
      {
	debug_printf ("BLKRRPART");
	if (!DeviceIoControl (get_handle (),
			      IOCTL_DISK_UPDATE_DRIVE_SIZE,
			      NULL, 0,
			      &di, sizeof (di),
			      &bytes_read, NULL))
	  {
	    __seterrno ();
	    return -1;
	  }
	return 0;
      }
    case BLKSSZGET:
      {
	debug_printf ("BLKSSZGET");
	if (!DeviceIoControl (get_handle (),
			      IOCTL_DISK_GET_DRIVE_GEOMETRY,
			      NULL, 0,
			      &di, sizeof (di),
			      &bytes_read, NULL))
	  {
	    __seterrno ();
	    return -1;
	  }
	debug_printf ("disk geometry: (%ld cyl)*(%ld trk)*(%ld sec)*(%ld bps)",
		      di.Cylinders.LowPart,
		      di.TracksPerCylinder,
		      di.SectorsPerTrack,
		      di.BytesPerSector);
	*(int *)buf = di.BytesPerSector;
	return 0;
      }
    default:
      return fhandler_dev_raw::ioctl (cmd, buf);
    }
}

