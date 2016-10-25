
extern "C" {
 int strlen(char* v);
 int write(int, char*, int);
  #define DUMMY(name) \
 int name() { \
   write(1, #name " not implemented\n", strlen(#name " not implemented\n")); \
   return 0; \
 }


 #define RDUMMY(name, ret) \
 int name() { \
   write(1, #name " not implemented\n", strlen(#name " not implemented\n")); \
   return ret; \
 }

  unsigned int ntohl(unsigned int v)
  {
    unsigned char*ptr = (unsigned char*)(void*)&v;
    return ptr[3] + (ptr[2] << 8) + (ptr[1] << 16) + (ptr[0]  << 24);
  }
  unsigned int htonl(unsigned int v)
  {
    return ntohl(v);
  }
  unsigned short ntohs(unsigned short v)
  {
    unsigned char*ptr = (unsigned char*)(void*)&v;
    return ptr[1] + (ptr[0] << 8);
  }
  unsigned short htons(unsigned short v)
  {
    return ntohs(v);
  }

  //DUMMY(inet_ntop)
  DUMMY(if_indextoname)
 DUMMY(accept)
 DUMMY(backtrace)
 DUMMY(backtrace_symbols)
 DUMMY(bind)
 DUMMY(chdir)
 DUMMY(chmod)
 DUMMY(chown)
 DUMMY(closedir)
 DUMMY(connect)
 DUMMY(dladdr)
 DUMMY(dlclose)
 DUMMY(dlerror)
 DUMMY(dlopen)
 DUMMY(dlsym)
 DUMMY(execvp)
 DUMMY(fchdir)
 DUMMY(fnmatch)
 DUMMY(freeaddrinfo)
 DUMMY(getaddrinfo)
 DUMMY(getegid)
 DUMMY(geteuid)
 DUMMY(gethostname)
 DUMMY(getlogin)
 DUMMY(getpeername)
 DUMMY(getpwuid)
 DUMMY(getsockname)
 DUMMY(getsockopt)
 DUMMY(getuid)
 DUMMY(open64)
 DUMMY(opendir)
 DUMMY(openlog)
 DUMMY(pipe)
 DUMMY(poll)
 DUMMY(readdir)
 DUMMY(readdir64)
 DUMMY(readdir64_r)
 //DUMMY(readlink)
 DUMMY(readv)
 DUMMY(recvmsg)
 DUMMY(select)
 DUMMY(sendmsg)
 DUMMY(setegid)
 DUMMY(seteuid)
 DUMMY(setgid)
 DUMMY(setsockopt)
 DUMMY(setuid)
 DUMMY(shutdown)
 DUMMY(sigaction)
 DUMMY(socket)
 DUMMY(statvfs64)
 DUMMY(symlink)
 DUMMY(sysconf)
 DUMMY(syslog)
 DUMMY(tcgetattr)
 DUMMY(tcsetattr)
 DUMMY(times)
 DUMMY(truncate64)
 DUMMY(utime)
 DUMMY(waitpid)
 DUMMY(__xstat64)
 DUMMY(if_nametoindex)
 //DUMMY(inet_pton)
 DUMMY(ioctl)
 DUMMY(listen)
 DUMMY(__lxstat64)
 DUMMY(statvfs)
 DUMMY(lstat)
 DUMMY(fchmodat)
 DUMMY(truncate)
 DUMMY(___xpg_strerror_r)
 DUMMY(getgid)
 DUMMY(gethostbyname)
 DUMMY(getservbyname)
 DUMMY(closelog)
 DUMMY(sendto)
 DUMMY(recvfrom)
}