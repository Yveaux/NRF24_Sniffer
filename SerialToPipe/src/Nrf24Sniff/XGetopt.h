// XGetopt.h  Version 1.1
//
// Author:  Hans Dietrich
//          hdietrich2@hotmail.com
//
// This software is released into the public domain.
// You are free to use it in any way you like.
//
// This software is provided "as is" with no expressed
// or implied warranty.  I accept no liability for any
// damage or loss of business that this software may cause.
//
// Ref: http://www.codeproject.com/Articles/1940/XGetopt-A-Unix-compatible-getopt-for-MFC-and-Win
//
///////////////////////////////////////////////////////////////////////////////

#ifndef XGETOPT_H
#define XGETOPT_H

extern int optind, opterr;
extern char *optarg;

int XGetopt(int argc, char *argv[], const char *optstring);

#endif //XGETOPT_H