/* getfacl.c

   Copyright 2000, 2001, 2002 Red Hat Inc.

   Written by Corinna Vinschen <vinschen@redhat.com>

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <string.h>

static const char version[] = "$Revision$";
static char *prog_name;

char *
permstr (mode_t perm)
{
  static char pbuf[4];

  pbuf[0] = (perm & S_IROTH) ? 'r' : '-';
  pbuf[1] = (perm & S_IWOTH) ? 'w' : '-';
  pbuf[2] = (perm & S_IXOTH) ? 'x' : '-';
  pbuf[3] = '\0';
  return pbuf;
}

const char *
username (uid_t uid)
{
  static char ubuf[256];
  struct passwd *pw;

  if ((pw = getpwuid (uid)))
    strcpy (ubuf, pw->pw_name);
  else
    sprintf (ubuf, "%lu <unknown>", (unsigned long)uid);
  return ubuf;
}

const char *
groupname (gid_t gid)
{
  static char gbuf[256];
  struct group *gr;

  if ((gr = getgrgid (gid)))
    strcpy (gbuf, gr->gr_name);
  else
    sprintf (gbuf, "%lu <unknown>", (unsigned long)gid);
  return gbuf;
}

static void
usage (FILE * stream)
{
  fprintf (stream, "Usage: %s [-adn] FILE [FILE2...]\n"
            "Display file and directory access control lists (ACLs).\n"
            "\n"
            "  -a, --all      display the filename, the owner, the group, and\n"
            "                 the ACL of the file\n"
            "  -d, --dir      display the filename, the owner, the group, and\n"
            "                 the default ACL of the directory, if it exists\n"
            "  -h, --help     output usage information and exit\n"
            "  -n, --noname   display user and group IDs instead of names\n"
            "  -v, --version  output version information and exit\n"
            "\n"
            "When multiple files are specified on the command line, a blank\n"
            "line separates the ACLs for each file.\n", prog_name);
  if (stream == stdout) 
    {
      fprintf (stream, ""
            "For each argument that is a regular file, special file or\n"
            "directory, getfacl displays the owner, the group, and the ACL.\n"
            "For directories getfacl displays additionally the default ACL.\n"
            "\n"
            "With no options specified, getfacl displays the filename, the\n"
            "owner, the group, and both the ACL and the default ACL, if it\n"
            "exists.\n"
            "\n"
            "The format for ACL output is as follows:\n"
            "     # file: filename\n"
            "     # owner: name or uid\n"
            "     # group: name or uid\n"
            "     user::perm\n"
            "     user:name or uid:perm\n"
            "     group::perm\n"
            "     group:name or gid:perm\n"
            "     mask:perm\n"
            "     other:perm\n"
            "     default:user::perm\n"
            "     default:user:name or uid:perm\n"
            "     default:group::perm\n"
            "     default:group:name or gid:perm\n"
            "     default:mask:perm\n"
            "     default:other:perm\n"
            "\n");
    }
}

struct option longopts[] = {
  {"all", no_argument, NULL, 'a'},
  {"dir", no_argument, NULL, 'd'},
  {"help", no_argument, NULL, 'h'},
  {"noname", no_argument, NULL, 'n'},
  {"version", no_argument, NULL, 'v'},
  {0, no_argument, NULL, 0}
};

static void
print_version ()
{
  const char *v = strchr (version, ':');
  int len;
  if (!v)
    {
      v = "?";
      len = 1;
    }
  else
    {
      v += 2;
      len = strchr (v, ' ') - v;
    }
  printf ("\
getfacl (cygwin) %.*s\n\
ACL Utility\n\
Copyright (c) 2000, 2001, 2002 Red Hat, Inc.\n\
Compiled on %s\n\
", len, v, __DATE__);
}

int
main (int argc, char **argv)
{
  extern int optind;
  int c, i;
  int aopt = 0;
  int dopt = 0;
  int nopt = 0;
  int first = 1;
  struct stat st;
  aclent_t acls[MAX_ACL_ENTRIES];

  prog_name = strrchr (argv[0], '/');
  if (prog_name == NULL)
    prog_name = strrchr (argv[0], '\\');
  if (prog_name == NULL)
    prog_name = argv[0];
  else
    prog_name++;

  while ((c = getopt_long (argc, argv, "adhnv", longopts, NULL)) != EOF)
    switch (c)
      {
      case 'a':
	aopt = 1;
	break;
      case 'd':
	dopt = 1;
	break;
      case 'h':
	usage (stdout);
	return 0;
      case 'n':
	nopt = 1;
	break;
      case 'v':
	print_version ();
	return 0;
      default:
	usage (stderr);
	return 1;
      }
  if (optind > argc - 1)
    {
      usage (stderr);
      return 1;
    }
  while ((c = optind++) < argc)
    {
      if (stat (argv[c], &st))
	{
	  perror (argv[0]);
	  continue;
	}
      if (!first)
	putchar ('\n');
      first = 0;
      printf ("# file: %s\n", argv[c]);
      if (nopt)
        {
	  printf ("# owner: %lu\n", (unsigned long)st.st_uid);
	  printf ("# group: %lu\n", (unsigned long)st.st_gid);
	}
      else
        {
	  printf ("# owner: %s\n", username (st.st_uid));
	  printf ("# group: %s\n", groupname (st.st_gid));
	}
      if ((c = acl (argv[c], GETACL, MAX_ACL_ENTRIES, acls)) < 0)
	{
	  perror (argv[0]);
	  continue;
	}
      for (i = 0; i < c; ++i)
	{
	  if (acls[i].a_type & ACL_DEFAULT)
	    {
	      if (aopt)
		continue;
	      printf ("default:");
	    }
	  else if (dopt)
	    continue;
	  switch (acls[i].a_type & ~ACL_DEFAULT)
	    {
	    case USER_OBJ:
	      printf ("user::");
	      break;
	    case USER:
	      if (nopt)
		printf ("user:%lu\n", (unsigned long)acls[i].a_id);
	      else
		printf ("user:%s:", username (acls[i].a_id));
	      break;
	    case GROUP_OBJ:
	      printf ("group::");
	      break;
	    case GROUP:
	      if (nopt)
		printf ("group:%lu\n", (unsigned long)acls[i].a_id);
	      else
		printf ("group:%s:", groupname (acls[i].a_id));
	      break;
	    case CLASS_OBJ:
	      printf ("mask:");
	      break;
	    case OTHER_OBJ:
	      printf ("other:");
	      break;
	    }
	  printf ("%s\n", permstr (acls[i].a_perm));
	}
    }
  return 0;
}
