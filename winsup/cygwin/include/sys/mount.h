#ifndef _SYS_MOUNT_H
#define _SYS_MOUNT_H

#ifdef __cplusplus
extern "C" {
#endif

enum
{
  MOUNT_SYMLINK =	0x001,	/* "mount point" is a symlink */
  MOUNT_BINARY =	0x002,	/* "binary" format read/writes */
  MOUNT_SYSTEM =	0x008,	/* mount point came from system table */
  MOUNT_EXEC   =	0x010,	/* Any file in the mounted directory gets 'x' bit */
  MOUNT_AUTO   =	0x020,	/* mount point refers to auto device mount */
  MOUNT_CYGWIN_EXEC =	0x040,	/* file or directory is or contains a cygwin
				   executable */
  MOUNT_MIXED	=	0x080,	/* reads are text, writes are binary */
};

int mount (const char *, const char *, unsigned __flags);
int umount (const char *);
int cygwin_umount (const char *__path, unsigned __flags);

#ifdef __cplusplus
};
#endif

#endif /* _SYS_MOUNT_H */
