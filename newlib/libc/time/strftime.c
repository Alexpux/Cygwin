/*
 * strftime.c
 * Original Author:	G. Haley
 * Additions from:	Eric Blake
 *
 * Places characters into the array pointed to by s as controlled by the string
 * pointed to by format. If the total number of resulting characters including
 * the terminating null character is not more than maxsize, returns the number
 * of characters placed into the array pointed to by s (not including the
 * terminating null character); otherwise zero is returned and the contents of
 * the array indeterminate.
 */

/*
FUNCTION
<<strftime>>---flexible calendar time formatter

INDEX
	strftime

ANSI_SYNOPSIS
	#include <time.h>
	size_t strftime(char *<[s]>, size_t <[maxsize]>,
			const char *<[format]>, const struct tm *<[timp]>);

TRAD_SYNOPSIS
	#include <time.h>
	size_t strftime(<[s]>, <[maxsize]>, <[format]>, <[timp]>)
	char *<[s]>;
	size_t <[maxsize]>;
	char *<[format]>;
	struct tm *<[timp]>;

DESCRIPTION
<<strftime>> converts a <<struct tm>> representation of the time (at
<[timp]>) into a null-terminated string, starting at <[s]> and occupying
no more than <[maxsize]> characters.

You control the format of the output using the string at <[format]>.
<<*<[format]>>> can contain two kinds of specifications: text to be
copied literally into the formatted string, and time conversion
specifications.  Time conversion specifications are two- and
three-character sequences beginning with `<<%>>' (use `<<%%>>' to
include a percent sign in the output).  Each defined conversion
specification selects only the specified field(s) of calendar time
data from <<*<[timp]>>>, and converts it to a string in one of the
following ways:

o+
o %a
A three-letter abbreviation for the day of the week. [tm_wday]

o %A
The full name for the day of the week, one of `<<Sunday>>',
`<<Monday>>', `<<Tuesday>>', `<<Wednesday>>', `<<Thursday>>',
`<<Friday>>', or `<<Saturday>>'. [tm_wday]

o %b
A three-letter abbreviation for the month name. [tm_mon]

o %B
The full name of the month, one of `<<January>>', `<<February>>',
`<<March>>', `<<April>>', `<<May>>', `<<June>>', `<<July>>',
`<<August>>', `<<September>>', `<<October>>', `<<November>>',
`<<December>>'. [tm_mon]

o %c
A string representing the complete date and time, in the form
`<<"%a %b %e %H:%M:%S %Y">>' (example "Mon Apr 01 13:13:13
1992"). [tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday]

o %C
The century, that is, the year divided by 100 then truncated.  For
4-digit years, the result is zero-padded and exactly two characters;
but for other years, there may a negative sign or more digits.  In
this way, `<<%C%y>>' is equivalent to `<<%Y>>'. [tm_year]
 
o %d
The day of the month, formatted with two digits (from `<<01>>' to
`<<31>>'). [tm_mday]

o %D
A string representing the date, in the form `<<"%m/%d/%y">>'.
[tm_mday, tm_mon, tm_year]

o %e
The day of the month, formatted with leading space if single digit
(from `<<1>>' to `<<31>>'). [tm_mday]

o %E<<x>>
In some locales, the E modifier selects alternative representations of
certain modifiers <<x>>.  But in the "C" locale supported by newlib,
it is ignored, and treated as %<<x>>.

o %F
A string representing the ISO 8601:2000 date format, in the form
`<<"%Y-%m-%d">>'. [tm_mday, tm_mon, tm_year]

o %g
The last two digits of the week-based year, see specifier %G (from
`<<00>>' to `<<99>>'). [tm_year, tm_wday, tm_yday]

o %G
The week-based year. In the ISO 8601:2000 calendar, week 1 of the year
includes January 4th, and begin on Mondays. Therefore, if January 1st,
2nd, or 3rd falls on a Sunday, that day and earlier belong to the last
week of the previous year; and if December 29th, 30th, or 31st falls
on Monday, that day and later belong to week 1 of the next year.  For
consistency with %Y, it always has at least four characters. 
Example: "%G" for Saturday 2nd January 1999 gives "1998", and for
Tuesday 30th December 1997 gives "1998". [tm_year, tm_wday, tm_yday]

o %h
A three-letter abbreviation for the month name (synonym for
"%b"). [tm_mon]

o %H
The hour (on a 24-hour clock), formatted with two digits (from
`<<00>>' to `<<23>>'). [tm_hour]

o %I
The hour (on a 12-hour clock), formatted with two digits (from
`<<01>>' to `<<12>>'). [tm_hour]

o %j
The count of days in the year, formatted with three digits
(from `<<001>>' to `<<366>>'). [tm_yday]

o %k
The hour (on a 24-hour clock), formatted with leading space if single
digit (from `<<0>>' to `<<23>>'). Non-POSIX extension. [tm_hour]

o %l
The hour (on a 12-hour clock), formatted with leading space if single
digit (from `<<1>>' to `<<12>>'). Non-POSIX extension. [tm_hour]

o %m
The month number, formatted with two digits (from `<<01>>' to `<<12>>').
[tm_mon]

o %M
The minute, formatted with two digits (from `<<00>>' to `<<59>>'). [tm_min]

o %n
A newline character (`<<\n>>').

o %O<<x>>
In some locales, the O modifier selects alternative digit characters
for certain modifiers <<x>>.  But in the "C" locale supported by newlib, it
is ignored, and treated as %<<x>>.

o %p
Either `<<AM>>' or `<<PM>>' as appropriate. [tm_hour]

o %r
The 12-hour time, to the second.  Equivalent to "%I:%M:%S %p". [tm_sec,
tm_min, tm_hour]

o %R
The 24-hour time, to the minute.  Equivalent to "%H:%M". [tm_min, tm_hour]

o %S
The second, formatted with two digits (from `<<00>>' to `<<60>>').  The
value 60 accounts for the occasional leap second. [tm_sec]

o %t
A tab character (`<<\t>>').

o %T
The 24-hour time, to the second.  Equivalent to "%H:%M:%S". [tm_sec,
tm_min, tm_hour]

o %u
The weekday as a number, 1-based from Monday (from `<<1>>' to
`<<7>>'). [tm_wday]

o %U
The week number, where weeks start on Sunday, week 1 contains the first
Sunday in a year, and earlier days are in week 0.  Formatted with two
digits (from `<<00>>' to `<<53>>').  See also <<%W>>. [tm_wday, tm_yday]

o %V
The week number, where weeks start on Monday, week 1 contains January 4th,
and earlier days are in the previous year.  Formatted with two digits
(from `<<01>>' to `<<53>>').  See also <<%G>>. [tm_year, tm_wday, tm_yday]

o %w
The weekday as a number, 0-based from Sunday (from `<<0>>' to `<<6>>').
[tm_wday]

o %W
The week number, where weeks start on Monday, week 1 contains the first
Monday in a year, and earlier days are in week 0.  Formatted with two
digits (from `<<00>>' to `<<53>>'). [tm_wday, tm_yday]

o %x
A string representing the complete date, equivalent to "%m/%d/%y".
[tm_mon, tm_mday, tm_year]

o %X
A string representing the full time of day (hours, minutes, and
seconds), equivalent to "%H:%M:%S". [tm_sec, tm_min, tm_hour]

o %y
The last two digits of the year (from `<<00>>' to `<<99>>'). [tm_year]

o %Y
The full year, equivalent to <<%C%y>>.  It will always have at least four
characters, but may have more.  The year is accurate even when tm_year
added to the offset of 1900 overflows an int. [tm_year]

o %z
The offset from UTC.  The format consists of a sign (negative is west of
Greewich), two characters for hour, then two characters for minutes
(-hhmm or +hhmm).  If tm_isdst is negative, the offset is unknown and no
output is generated; if it is zero, the offset is the standard offset for
the current time zone; and if it is positive, the offset is the daylight
savings offset for the current timezone. The offset is determined from
the TZ environment variable, as if by calling tzset(). [tm_isdst]

o %Z
The time zone name.  If tm_isdst is negative, no output is generated.
Otherwise, the time zone name is based on the TZ environment variable,
as if by calling tzset(). [tm_isdst]

o %%
A single character, `<<%>>'.
o-

RETURNS
When the formatted time takes up no more than <[maxsize]> characters,
the result is the length of the formatted string.  Otherwise, if the
formatting operation was abandoned due to lack of room, the result is
<<0>>, and the string starting at <[s]> corresponds to just those
parts of <<*<[format]>>> that could be completely filled in within the
<[maxsize]> limit.

PORTABILITY
ANSI C requires <<strftime>>, but does not specify the contents of
<<*<[s]>>> when the formatted string would require more than
<[maxsize]> characters.  Unrecognized specifiers and fields of
<<timp>> that are out of range cause undefined results.  Since some
formats expand to 0 bytes, it is wise to set <<*<[s]>>> to a nonzero
value beforehand to distinguish between failure and an empty string.
This implementation does not support <<s>> being NULL, nor overlapping
<<s>> and <<format>>.

<<strftime>> requires no supporting OS subroutines.
*/

#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "local.h"

static _CONST int dname_len[7] =
{6, 6, 7, 9, 8, 6, 8};

static _CONST char *_CONST dname[7] =
{"Sunday", "Monday", "Tuesday", "Wednesday",
 "Thursday", "Friday", "Saturday"};

static _CONST int mname_len[12] =
{7, 8, 5, 5, 3, 4, 4, 6, 9, 7, 8, 8};

static _CONST char *_CONST mname[12] =
{"January", "February", "March", "April",
 "May", "June", "July", "August", "September", "October", "November",
 "December"};

/* Using the tm_year, tm_wday, and tm_yday components of TIM_P, return
   -1, 0, or 1 as the adjustment to add to the year for the ISO week
   numbering used in "%g%G%V", avoiding overflow.  */
static int
_DEFUN (iso_year_adjust, (tim_p),
	_CONST struct tm *tim_p)
{
  /* Account for fact that tm_year==0 is year 1900.  */
  int leap = isleap (tim_p->tm_year + (YEAR_BASE
				       - (tim_p->tm_year < 0 ? 0 : 2000)));

  /* Pack the yday, wday, and leap year into a single int since there are so
     many disparate cases.  */
#define PACK(yd, wd, lp) (((yd) << 4) + (wd << 1) + (lp))
  switch (PACK (tim_p->tm_yday, tim_p->tm_wday, leap))
    {
    case PACK (0, 5, 0): /* Jan 1 is Fri, not leap.  */
    case PACK (0, 6, 0): /* Jan 1 is Sat, not leap.  */
    case PACK (0, 0, 0): /* Jan 1 is Sun, not leap.  */
    case PACK (0, 5, 1): /* Jan 1 is Fri, leap year.  */
    case PACK (0, 6, 1): /* Jan 1 is Sat, leap year.  */
    case PACK (0, 0, 1): /* Jan 1 is Sun, leap year.  */
    case PACK (1, 6, 0): /* Jan 2 is Sat, not leap.  */
    case PACK (1, 0, 0): /* Jan 2 is Sun, not leap.  */
    case PACK (1, 6, 1): /* Jan 2 is Sat, leap year.  */
    case PACK (1, 0, 1): /* Jan 2 is Sun, leap year.  */
    case PACK (2, 0, 0): /* Jan 3 is Sun, not leap.  */
    case PACK (2, 0, 1): /* Jan 3 is Sun, leap year.  */
      return -1; /* Belongs to last week of previous year.  */
    case PACK (362, 1, 0): /* Dec 29 is Mon, not leap.  */
    case PACK (363, 1, 1): /* Dec 29 is Mon, leap year.  */
    case PACK (363, 1, 0): /* Dec 30 is Mon, not leap.  */
    case PACK (363, 2, 0): /* Dec 30 is Tue, not leap.  */
    case PACK (364, 1, 1): /* Dec 30 is Mon, leap year.  */
    case PACK (364, 2, 1): /* Dec 30 is Tue, leap year.  */
    case PACK (364, 1, 0): /* Dec 31 is Mon, not leap.  */
    case PACK (364, 2, 0): /* Dec 31 is Tue, not leap.  */
    case PACK (364, 3, 0): /* Dec 31 is Wed, not leap.  */
    case PACK (365, 1, 1): /* Dec 31 is Mon, leap year.  */
    case PACK (365, 2, 1): /* Dec 31 is Tue, leap year.  */
    case PACK (365, 3, 1): /* Dec 31 is Wed, leap year.  */
      return 1; /* Belongs to first week of next year.  */
    }
  return 0; /* Belongs to specified year.  */
#undef PACK
}

size_t
_DEFUN (strftime, (s, maxsize, format, tim_p),
	char *s _AND
	size_t maxsize _AND
	_CONST char *format _AND
	_CONST struct tm *tim_p)
{
  size_t count = 0;
  int i;

  for (;;)
    {
      while (*format && *format != '%')
	{
	  if (count < maxsize - 1)
	    s[count++] = *format++;
	  else
	    return 0;
	}

      if (*format == '\0')
	break;

      format++;
      if (*format == 'E' || *format == 'O')
	format++;

      switch (*format)
	{
	case 'a':
	  for (i = 0; i < 3; i++)
	    {
	      if (count < maxsize - 1)
		s[count++] =
		  dname[tim_p->tm_wday][i];
	      else
		return 0;
	    }
	  break;
	case 'A':
	  for (i = 0; i < dname_len[tim_p->tm_wday]; i++)
	    {
	      if (count < maxsize - 1)
		s[count++] =
		  dname[tim_p->tm_wday][i];
	      else
		return 0;
	    }
	  break;
	case 'b':
	case 'h':
	  for (i = 0; i < 3; i++)
	    {
	      if (count < maxsize - 1)
		s[count++] =
		  mname[tim_p->tm_mon][i];
	      else
		return 0;
	    }
	  break;
	case 'B':
	  for (i = 0; i < mname_len[tim_p->tm_mon]; i++)
	    {
	      if (count < maxsize - 1)
		s[count++] =
		  mname[tim_p->tm_mon][i];
	      else
		return 0;
	    }
	  break;
	case 'c':
	  {
	    /* Length is not known because of %C%y, so recurse. */
	    size_t adjust = strftime (&s[count], maxsize - count,
				      "%a %b %e %H:%M:%S %C%y", tim_p);
	    if (adjust > 0)
	      count += adjust;
	    else
	      return 0;
	  }
	  break;
	case 'C':
	  {
	    /* Examples of (tm_year + YEAR_BASE) that show how %Y == %C%y
	       with 32-bit int.
	       %Y		%C		%y
	       2147485547	21474855	47
	       10000		100		00
	       9999		99		99
	       0999		09		99
	       0099		00		99
	       0001		00		01
	       0000		00		00
	       -001		-0		01
	       -099		-0		99
	       -999		-9		99
	       -1000		-10		00
	       -10000		-100		00
	       -2147481748	-21474817	48

	       Be careful of both overflow and sign adjustment due to the
	       asymmetric range of years.
	    */
	    int neg = tim_p->tm_year < -YEAR_BASE;
	    int century = tim_p->tm_year >= 0
	      ? tim_p->tm_year / 100 + YEAR_BASE / 100
	      : abs (tim_p->tm_year + YEAR_BASE) / 100;
            count += snprintf (&s[count], maxsize - count, "%s%.*d",
                               neg ? "-" : "", 2 - neg, century);
            if (count >= maxsize)
              return 0;
	  }
	  break;
	case 'd':
	case 'e':
	  if (count < maxsize - 2)
	    {
	      sprintf (&s[count], *format == 'd' ? "%.2d" : "%2d",
		       tim_p->tm_mday);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 'D':
	case 'x':
	  /* %m/%d/%y */
	  if (count < maxsize - 8)
	    {
	      sprintf (&s[count], "%.2d/%.2d/%.2d",
		       tim_p->tm_mon + 1, tim_p->tm_mday,
		       tim_p->tm_year >= 0 ? tim_p->tm_year % 100
		       : abs (tim_p->tm_year + YEAR_BASE) % 100);
	      count += 8;
	    }
	  else
	    return 0;
	  break;
        case 'F':
	  {
	    /* Length is not known because of %C%y, so recurse. */
	    size_t adjust = strftime (&s[count], maxsize - count,
				      "%C%y-%m-%d", tim_p);
	    if (adjust > 0)
	      count += adjust;
	    else
	      return 0;
	  }
          break;
        case 'g':
	  if (count < maxsize - 2)
	    {
	      /* Be careful of both overflow and negative years, thanks to
		 the asymmetric range of years.  */
	      int adjust = iso_year_adjust (tim_p);
	      int year = tim_p->tm_year >= 0 ? tim_p->tm_year % 100
		: abs (tim_p->tm_year + YEAR_BASE) % 100;
	      if (adjust < 0 && tim_p->tm_year <= -YEAR_BASE)
		adjust = 1;
	      else if (adjust > 0 && tim_p->tm_year < -YEAR_BASE)
		adjust = -1;
	      sprintf (&s[count], "%.2d",
		       ((year + adjust) % 100 + 100) % 100);
	      count += 2;
	    }
	  else
	    return 0;
          break;
        case 'G':
	  {
	    /* See the comments for 'C' and 'Y'; this is a variable length
	       field.  Although there is no requirement for a minimum number
	       of digits, we use 4 for consistency with 'Y'.  */
	    int neg = tim_p->tm_year < -YEAR_BASE;
	    int adjust = iso_year_adjust (tim_p);
	    int century = tim_p->tm_year >= 0
	      ? tim_p->tm_year / 100 + YEAR_BASE / 100
	      : abs (tim_p->tm_year + YEAR_BASE) / 100;
	    int year = tim_p->tm_year >= 0 ? tim_p->tm_year % 100
	      : abs (tim_p->tm_year + YEAR_BASE) % 100;
	    if (adjust < 0 && tim_p->tm_year <= -YEAR_BASE)
	      neg = adjust = 1;
	    else if (adjust > 0 && neg)
	      adjust = -1;
	    year += adjust;
	    if (year == -1)
	      {
		year = 99;
		--century;
	      }
	    else if (year == 100)
	      {
		year = 0;
		++century;
	      }
            count += snprintf (&s[count], maxsize - count, "%s%.*d%.2d",
                               neg ? "-" : "", 2 - neg, century, year);
            if (count >= maxsize)
              return 0;
	  }
          break;
	case 'H':
	case 'k':
	  if (count < maxsize - 2)
	    {
	      sprintf (&s[count], *format == 'k' ? "%2d" : "%.2d",
		       tim_p->tm_hour);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 'I':
	case 'l':
	  if (count < maxsize - 2)
	    {
	      if (tim_p->tm_hour == 0 ||
		  tim_p->tm_hour == 12)
		{
		  s[count++] = '1';
		  s[count++] = '2';
		}
	      else
		{
		  sprintf (&s[count], *format == 'I' ? "%.2d" : "%2d",
			   tim_p->tm_hour % 12);
		  count += 2;
		}
	    }
	  else
	    return 0;
	  break;
	case 'j':
	  if (count < maxsize - 3)
	    {
	      sprintf (&s[count], "%.3d",
		       tim_p->tm_yday + 1);
	      count += 3;
	    }
	  else
	    return 0;
	  break;
	case 'm':
	  if (count < maxsize - 2)
	    {
	      sprintf (&s[count], "%.2d",
		       tim_p->tm_mon + 1);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 'M':
	  if (count < maxsize - 2)
	    {
	      sprintf (&s[count], "%.2d",
		       tim_p->tm_min);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 'n':
	  if (count < maxsize - 1)
	    s[count++] = '\n';
	  else
	    return 0;
	  break;
	case 'p':
	  if (count < maxsize - 2)
	    {
	      if (tim_p->tm_hour < 12)
		s[count++] = 'A';
	      else
		s[count++] = 'P';

	      s[count++] = 'M';
	    }
	  else
	    return 0;
	  break;
	case 'r':
	  if (count < maxsize - 11)
	    {
	      if (tim_p->tm_hour == 0 ||
		  tim_p->tm_hour == 12)
		{
		  s[count++] = '1';
		  s[count++] = '2';
		}
	      else
		{
		  sprintf (&s[count], "%.2d", tim_p->tm_hour % 12);
		  count += 2;
		}
	      s[count++] = ':';
	      sprintf (&s[count], "%.2d",
		       tim_p->tm_min);
	      count += 2;
	      s[count++] = ':';
	      sprintf (&s[count], "%.2d",
		       tim_p->tm_sec);
	      count += 2;
	      s[count++] = ' ';
	      if (tim_p->tm_hour < 12)
		s[count++] = 'A';
	      else
		s[count++] = 'P';

	      s[count++] = 'M';
	    }
	  else
	    return 0;
	  break;
        case 'R':
          if (count < maxsize - 5)
            {
              sprintf (&s[count], "%.2d:%.2d", tim_p->tm_hour, tim_p->tm_min);
              count += 5;
            }
          else
            return 0;
          break;
	case 'S':
	  if (count < maxsize - 2)
	    {
	      sprintf (&s[count], "%.2d",
		       tim_p->tm_sec);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 't':
	  if (count < maxsize - 1)
	    s[count++] = '\t';
	  else
	    return 0;
	  break;
        case 'T':
        case 'X':
          if (count < maxsize - 8)
            {
              sprintf (&s[count], "%.2d:%.2d:%.2d", tim_p->tm_hour,
                       tim_p->tm_min, tim_p->tm_sec);
              count += 8;
            }
          else
            return 0;
          break;
        case 'u':
          if (count < maxsize - 1)
            {
              if (tim_p->tm_wday == 0)
                s[count++] = '7';
              else
                s[count++] = '0' + tim_p->tm_wday;
            }
          else
            return 0;
          break;
	case 'U':
	  if (count < maxsize - 2)
	    {
	      sprintf (&s[count], "%.2d",
		       (tim_p->tm_yday + 7 -
			tim_p->tm_wday) / 7);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
        case 'V':
	  if (count < maxsize - 2)
	    {
	      int adjust = iso_year_adjust (tim_p);
	      int wday = (tim_p->tm_wday) ? tim_p->tm_wday - 1 : 6;
	      int week = (tim_p->tm_yday + 10 - wday) / 7;
	      if (adjust > 0)
		week = 1;
	      else if (adjust < 0)
		/* Previous year has 53 weeks if current year starts on
		   Fri, and also if current year starts on Sat and
		   previous year was leap year.  */
		week = 52 + (4 >= (wday - tim_p->tm_yday
				   - isleap (tim_p->tm_year
					     + (YEAR_BASE - 1
						- (tim_p->tm_year < 0
						   ? 0 : 2000)))));
	      sprintf (&s[count], "%.2d", week);
	      count += 2;
	    }
	  else
	    return 0;
          break;
	case 'w':
	  if (count < maxsize - 1)
            s[count++] = '0' + tim_p->tm_wday;
	  else
	    return 0;
	  break;
	case 'W':
	  if (count < maxsize - 2)
	    {
	      int wday = (tim_p->tm_wday) ? tim_p->tm_wday - 1 : 6;
	      sprintf (&s[count], "%.2d",
		       (tim_p->tm_yday + 7 - wday) / 7);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 'y':
	  if (count < maxsize - 2)
	    {
	      /* Be careful of both overflow and negative years, thanks to
		 the asymmetric range of years.  */
	      int year = tim_p->tm_year >= 0 ? tim_p->tm_year % 100
		: abs (tim_p->tm_year + YEAR_BASE) % 100;
	      sprintf (&s[count], "%.2d", year);
	      count += 2;
	    }
	  else
	    return 0;
	  break;
	case 'Y':
	  {
	    /* Length is not known because of %C%y, so recurse. */
	    size_t adjust = strftime (&s[count], maxsize - count,
				      "%C%y", tim_p);
	    if (adjust > 0)
	      count += adjust;
	    else
	      return 0;
	  }
	  break;
        case 'z':
          if (tim_p->tm_isdst >= 0)
            {
	      if (count < maxsize - 5)
		{
		  long offset;
		  __tzinfo_type *tz = __gettzinfo ();
		  TZ_LOCK;
		  /* The sign of this is exactly opposite the envvar TZ.  We
		     could directly use the global _timezone for tm_isdst==0,
		     but have to use __tzrule for daylight savings.  */
		  offset = -tz->__tzrule[tim_p->tm_isdst > 0].offset;
		  TZ_UNLOCK;
		  sprintf (&s[count], "%+03ld%.2ld", offset / SECSPERHOUR,
			   labs (offset / SECSPERMIN) % 60L);
		  count += 5;
		}
	      else
		return 0;
            }
          break;
	case 'Z':
	  if (tim_p->tm_isdst >= 0)
	    {
	      int size;
	      TZ_LOCK;
	      size = strlen(_tzname[tim_p->tm_isdst > 0]);
	      for (i = 0; i < size; i++)
		{
		  if (count < maxsize - 1)
		    s[count++] = _tzname[tim_p->tm_isdst > 0][i];
		  else
		    {
		      TZ_UNLOCK;
		      return 0;
		    }
		}
	      TZ_UNLOCK;
	    }
	  break;
	case '%':
	  if (count < maxsize - 1)
	    s[count++] = '%';
	  else
	    return 0;
	  break;
	}
      if (*format)
	format++;
      else
	break;
    }
  if (maxsize)
    s[count] = '\0';

  return count;
}
