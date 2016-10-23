
#ifdef __cplusplus
#include <functional>
namespace std
{
  class recursive_mutex
  {
  public:
    void lock() {}
    void unlock() {}
  };
  class mutex: public recursive_mutex
  {
    
  };
  
  class thread
  {
  public:
    typedef unsigned int id;
    thread() {}
    thread(std::function<void()>) {}
    void detach() {}
    void join() {}
  };
  class condition_variable
  {
  public:
    template<typename... T> void wait(T...) {}
    void notify_one() {}
    void notify_all() {}
  };
  template<typename T>
  class unique_lock
  {
  public:
    unique_lock() {}
    unique_lock(T&) {}
  };
  template<typename T> class lock_guard: public unique_lock<T>
  {
  public:
    template<typename U>
    lock_guard(U&) {}
  };
  class this_thread
  {
  public:
    static unsigned int get_id() { return 1;}
  };
}

#include <boost/date_time/posix_time/posix_time.hpp>
namespace boost
{
  struct once_flag
  {
    once_flag():init(false) {}
    bool init;
  };
  template< class Callable, class... Args >
  void call_once(once_flag& flag, Callable&& f, Args&&... args )
  {
    if (flag.init)
      return;
    flag.init = true;
    f(args...);
  }

  using mutex = std::mutex;
  using condition_variable = std::condition_variable;
  template<typename T>
  class unique_lock
   : public std::unique_lock<T>
   {
   public:
     unique_lock(T&) {}
   };

 namespace posix_time
 {
   class microsec_clock
   {
   public:
     static boost::posix_time::ptime universal_time()
     {
       return  boost::posix_time::ptime();
     }
     static boost::posix_time::ptime local_time()
     {
       return  boost::posix_time::ptime();
     }
   };
 }
 /*
 namespace date_time
 {
   template<typename T>
   class microsec_clock<T>
   : public posix_time::microsec_clock<T>
   {
   };
 }
 */
}
#endif
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>

typedef unsigned long rlim_t;
struct rlimit {
  rlim_t rlim_cur;  /* Soft limit */
  rlim_t rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};
#define RLIM_INFINITY -1
#define RLIMIT_STACK 42
#define PF_UNSPEC       0       /* Unspecified.  */
#define PF_LOCAL        1       /* Local to host (pipes and file-domain).  */
#define PF_UNIX         PF_LOCAL /* POSIX name for PF_LOCAL.  */
#define AF_UNIX PF_UNIX
#define AF_UNSPEC PF_UNSPEC
#define PF_INET         2
#define AF_INET         2
#define PF_INET6        10
#define AF_INET6        10
# define HOST_NOT_FOUND 1       /* Authoritative Answer Host not found.  */
# define TRY_AGAIN      2       /* Non-Authoritative Host not found,
                                   or SERVERFAIL.  */
# define NO_RECOVERY    3       /* Non recoverable errors, FORMERR, REFUSED,
                                   NOTIMP.  */
# define NO_DATA        4       /* Valid name, no data record of requested
                                   type.  */
# define EAI_BADFLAGS     -1    /* Invalid value for `ai_flags' field.  */
# define EAI_NONAME       -2    /* NAME or SERVICE is unknown.  */
# define EAI_AGAIN        -3    /* Temporary failure in name resolution.  */
# define EAI_FAIL         -4    /* Non-recoverable failure in name res.  */
# define EAI_FAMILY       -6    /* `ai_family' not supported.  */
# define EAI_SOCKTYPE     -7    /* `ai_socktype' not supported.  */
# define EAI_SERVICE      -8    /* SERVICE not supported for `ai_socktype'.  */
# define EAI_MEMORY       -10   /* Memory allocation failure.  */
# define EAI_SYSTEM       -11   /* System error returned in `errno'.  */
# define EAI_OVERFLOW     -12   /* Argument buffer overflow.  */


#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

# define NI_NUMERICHOST 1       /* Don't try to look up hostname.  */
# define NI_NUMERICSERV 2       /* Don't convert port number to name.  */
# define NI_NOFQDN      4       /* Only return nodename portion.  */
# define NI_NAMEREQD    8       /* Don't return numeric addresses.  */
# define NI_DGRAM       16      /* Look up UDP service rather than TCP.  */

#  define NI_MAXHOST      1025
#  define NI_MAXSERV      32

enum {
  IPPROTO_IP = 0,               /* Dummy protocol for TCP               */
#define IPPROTO_IP              IPPROTO_IP
  IPPROTO_ICMP = 1,             /* Internet Control Message Protocol    */
#define IPPROTO_ICMP            IPPROTO_ICMP
  IPPROTO_IGMP = 2,             /* Internet Group Management Protocol   */
#define IPPROTO_IGMP            IPPROTO_IGMP
  IPPROTO_IPIP = 4,             /* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_IPIP            IPPROTO_IPIP
  IPPROTO_TCP = 6,              /* Transmission Control Protocol        */
#define IPPROTO_TCP             IPPROTO_TCP
  IPPROTO_EGP = 8,              /* Exterior Gateway Protocol            */
#define IPPROTO_EGP             IPPROTO_EGP
  IPPROTO_PUP = 12,             /* PUP protocol                         */
#define IPPROTO_PUP             IPPROTO_PUP
  IPPROTO_UDP = 17,             /* User Datagram Protocol               */
#define IPPROTO_UDP             IPPROTO_UDP
  IPPROTO_IDP = 22,             /* XNS IDP protocol                     */
#define IPPROTO_IDP             IPPROTO_IDP
  IPPROTO_TP = 29,              /* SO Transport Protocol Class 4        */
#define IPPROTO_TP              IPPROTO_TP
  IPPROTO_DCCP = 33,            /* Datagram Congestion Control Protocol */
#define IPPROTO_DCCP            IPPROTO_DCCP
  IPPROTO_IPV6 = 41,            /* IPv6-in-IPv4 tunnelling              */
#define IPPROTO_IPV6            IPPROTO_IPV6
  IPPROTO_RSVP = 46,            /* RSVP Protocol                        */
#define IPPROTO_RSVP            IPPROTO_RSVP
  IPPROTO_GRE = 47,             /* Cisco GRE tunnels (rfc 1701,1702)    */
#define IPPROTO_GRE             IPPROTO_GRE
  IPPROTO_ESP = 50,             /* Encapsulation Security Payload protocol */
#define IPPROTO_ESP             IPPROTO_ESP
  IPPROTO_AH = 51,              /* Authentication Header protocol       */
#define IPPROTO_AH              IPPROTO_AH
  IPPROTO_MTP = 92,             /* Multicast Transport Protocol         */
#define IPPROTO_MTP             IPPROTO_MTP
  IPPROTO_BEETPH = 94,          /* IP option pseudo header for BEET     */
#define IPPROTO_BEETPH          IPPROTO_BEETPH
  IPPROTO_ENCAP = 98,           /* Encapsulation Header                 */
  IPPROTO_ICMPV6 = 58,
};

#define SOMAXCONN	128

enum
  {
    MSG_OOB             = 0x01, /* Process out-of-band data.  */
#define MSG_OOB         MSG_OOB
    MSG_PEEK            = 0x02, /* Peek at incoming messages.  */
#define MSG_PEEK        MSG_PEEK
    MSG_DONTROUTE       = 0x04, /* Don't use local routing.  */
#define MSG_DONTROUTE   MSG_DONTROUTE
#ifdef __USE_GNU
    /* DECnet uses a different name.  */
    MSG_TRYHARD         = MSG_DONTROUTE,
# define MSG_TRYHARD    MSG_DONTROUTE
#endif
    MSG_CTRUNC          = 0x08, /* Control data lost before delivery.  */
#define MSG_CTRUNC      MSG_CTRUNC
    MSG_PROXY           = 0x10, /* Supply or ask second address.  */
#define MSG_PROXY       MSG_PROXY
    MSG_TRUNC           = 0x20,
#define MSG_TRUNC       MSG_TRUNC
    MSG_DONTWAIT        = 0x40, /* Nonblocking IO.  */
#define MSG_DONTWAIT    MSG_DONTWAIT
    MSG_EOR             = 0x80, /* End of record.  */
#define MSG_EOR         MSG_EOR
    MSG_WAITALL         = 0x100, /* Wait for a full request.  */
#define MSG_WAITALL     MSG_WAITALL
    MSG_FIN             = 0x200,
#define MSG_FIN         MSG_FIN
    MSG_SYN             = 0x400,
#define MSG_SYN         MSG_SYN
    MSG_CONFIRM         = 0x800, /* Confirm path validity.  */
#define MSG_CONFIRM     MSG_CONFIRM
    MSG_RST             = 0x1000,
#define MSG_RST         MSG_RST
    MSG_ERRQUEUE        = 0x2000, /* Fetch message from error queue.  */
#define MSG_ERRQUEUE    MSG_ERRQUEUE
    MSG_NOSIGNAL        = 0x4000, /* Do not generate SIGPIPE.  */
#define MSG_NOSIGNAL    MSG_NOSIGNAL
    MSG_MORE            = 0x8000,  /* Sender will send more.  */
#define MSG_MORE        MSG_MORE
    MSG_WAITFORONE      = 0x10000, /* Wait for at least one packet to return.*/
#define MSG_WAITFORONE  MSG_WAITFORONE
    MSG_FASTOPEN        = 0x20000000, /* Send data in TCP SYN.  */
#define MSG_FASTOPEN    MSG_FASTOPEN
    MSG_CMSG_CLOEXEC    = 0x40000000    /* Set close_on_exit for file
                                           descriptor received through
                                           SCM_RIGHTS.  */
#define MSG_CMSG_CLOEXEC MSG_CMSG_CLOEXEC
  };


enum
{
  SHUT_RD = 0,          /* No more receptions.  */
#define SHUT_RD         SHUT_RD
  SHUT_WR,              /* No more transmissions.  */
#define SHUT_WR         SHUT_WR
  SHUT_RDWR             /* No more receptions or transmissions.  */
#define SHUT_RDWR       SHUT_RDWR
};



enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,               /* Connectionless, unreliable datagrams
                                   of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,                 /* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,                 /* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,           /* Sequenced, reliable, connection-based,
                                   datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_DCCP = 6,                /* Datagram Congestion Control Protocol.  */
#define SOCK_DCCP SOCK_DCCP
  SOCK_PACKET = 10,             /* Linux specific way of getting packets
                                   at the dev level.  For writing rarp and
                                   other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET

  /* Flags to be ORed into the type parameter of socket and socketpair and
     used for the flags parameter of paccept.  */

  SOCK_CLOEXEC = 02000000,      /* Atomically set close-on-exec flag for the
                                   new descriptor(s).  */
#define SOCK_CLOEXEC SOCK_CLOEXEC
  SOCK_NONBLOCK = 00004000      /* Atomically mark descriptor(s) as
                                   non-blocking.  */
#define SOCK_NONBLOCK SOCK_NONBLOCK
};

#define	INADDR_ANY		(0x00000000)

# define AI_PASSIVE     0x0001  /* Socket address is intended for `bind'.  */
# define AI_CANONNAME   0x0002  /* Request for canonical name.  */
# define AI_NUMERICHOST 0x0004  /* Don't use name resolution.  */
# define AI_V4MAPPED    0x0008  /* IPv4 mapped addresses are acceptable.  */
# define AI_ALL         0x0010  /* Return IPv4 mapped and IPv6 addresses.  */
# define AI_ADDRCONFIG  0x0020  /* Use configuration of this host to choose
                                   returned address type..  */
#define        IP_OPTIONS      4       /* ip_opts; IP per-packet options.  */
#define        IP_HDRINCL      3       /* int; Header is included with data.  */
#define        IP_TOS          1       /* int; IP type of service and precedence.  */
#define        IP_TTL          2       /* int; IP time to live.  */
#define        IP_RECVOPTS     6       /* bool; Receive all IP options w/datagram.  */

#define IP_MULTICAST_IF 32      /* in_addr; set/get IP multicast i/f */
#define IP_MULTICAST_TTL 33     /* u_char; set/get IP multicast ttl */
#define IP_MULTICAST_LOOP 34    /* i_char; set/get IP multicast loopback */
#define IP_ADD_MEMBERSHIP 35    /* ip_mreq; add an IP group membership */
#define IP_DROP_MEMBERSHIP 36   /* ip_mreq; drop an IP group membership */
#define IP_UNBLOCK_SOURCE 37    /* ip_mreq_source: unblock data from source */
#define IP_BLOCK_SOURCE 38      /* ip_mreq_source: block data from source */
#define IP_ADD_SOURCE_MEMBERSHIP 39 /* ip_mreq_source: join source group */
#define IP_DROP_SOURCE_MEMBERSHIP 40 /* ip_mreq_source: leave source group */
#define IP_MSFILTER 41

#define IPV6_NEXTHOP            9
#define IPV6_AUTHHDR            10
#define IPV6_UNICAST_HOPS       16
#define IPV6_MULTICAST_IF       17
#define IPV6_MULTICAST_HOPS     18
#define IPV6_MULTICAST_LOOP     19
#define IPV6_JOIN_GROUP         20
#define IPV6_LEAVE_GROUP        21
#define IPV6_ROUTER_ALERT       22
#define IPV6_MTU_DISCOVER       23
#define IPV6_MTU                24
#define IPV6_RECVERR            25
#define IPV6_V6ONLY             26
#define IPV6_JOIN_ANYCAST       27
#define IPV6_LEAVE_ANYCAST      28
#define IPV6_IPSEC_POLICY       34
#define IPV6_XFRM_POLICY        35

#define IP_RECVERR	11
#define SOL_IP	0
#define SOL_IPV6        41

typedef unsigned long socklen_t;
struct sockaddr
{
  unsigned short  sa_family  ;//Address family. 
  char         sa_data[1]  ;//Socket address (variable-length data).
};
struct in_addr
{
  unsigned int s_addr;
};
typedef struct in_addr in_addr_t;

struct in6_addr {
        union {
                unsigned char            u6_addr8[16];
                unsigned short          u6_addr16[8];
                unsigned long          u6_addr32[4];
        } in6_u;
#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32
};

#define __SOCK_SIZE__   16
struct sockaddr_in
{
  short    sin_family; /* address family: AF_INET */
  unsigned short      sin_port;   /* port in network byte order */
  struct in_addr sin_addr;   /* internet address */
    /* Pad to size of `struct sockaddr'. */
  unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};
struct sockaddr_un
{
  short sun_family;               /* AF_UNIX */
  char        sun_path[108];            /* pathname */
};
struct sockaddr_in6
{
  short     sin6_family;   /* AF_INET6 */
  unsigned short       sin6_port;     /* port number */
  uint32_t        sin6_flowinfo; /* IPv6 flow information */
  struct in6_addr sin6_addr;     /* IPv6 address */
  uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
};
struct sockaddr_storage
{
  unsigned short   ss_family;
  unsigned char __pad[__SOCK_SIZE__ - sizeof(unsigned short)];
};
struct msghdr
{
  void          *msg_name        ;//Optional address. 
  socklen_t      msg_namelen     ;//Size of address. 
  struct iovec  *msg_iov         ;//Scatter/gather array. 
  int            msg_iovlen      ;//Members in msg_iov. 
  void          *msg_control     ;//Ancillary data; see below. 
  socklen_t      msg_controllen  ;//Ancillary data buffer len. 
  int            msg_flags       ;//Flags on received message.
};
struct linger
{
  int l_linger;
  int l_onoff;
};
struct ip_mreq
{
  /* IP multicast address of group.  */
  struct in_addr imr_multiaddr;
  
  /* Local IP address of interface.  */
  struct in_addr imr_interface;

};
struct ipv6_mreq
{
  /* IPv6 multicast address of group */
    struct in6_addr ipv6mr_multiaddr;

    /* local interface */
    unsigned int ipv6mr_interface;

};
struct addrinfo
{
   int              ai_flags;
   int              ai_family;
   int              ai_socktype;
   int              ai_protocol;
   socklen_t        ai_addrlen;
   struct sockaddr *ai_addr;
   char            *ai_canonname;
   struct addrinfo *ai_next;
};
struct iovec
{
  void   *iov_base  ;//Base address of a memory region for input or output. 
  size_t  iov_len   ;//The size of the memory pointed to by iov_base. 
};

struct hostent {
  char  *h_name;            /* official name of host */
  char **h_aliases;         /* alias list */
  int    h_addrtype;        /* host address type */
  int    h_length;          /* length of address */
  char **h_addr_list;       /* list of addresses */
};
#define h_addr h_addr_list[0] /* for backward compatibility */

struct servent {
  char  *s_name;       /* official service name */
  char **s_aliases;    /* alias list */
  int    s_port;       /* port number */
  char  *s_proto;      /* protocol to use */
};

#define ECHO    0000010
#define ECHOE   0000020
#define ECHOK   0000040
#define ECHONL  0000100
#define TCSANOW         0
#define TCSADRAIN       1
#define TCSAFLUSH       2
#define TCIFLUSH        0
#define TCOFLUSH        1
#define TCIOFLUSH       2
#define NCCS 32
typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;
struct termios {
  tcflag_t c_iflag;      /* input modes */
  tcflag_t c_oflag;      /* output modes */
  tcflag_t c_cflag;      /* control modes */
  tcflag_t c_lflag;      /* local modes */
  cc_t     c_cc[NCCS];   /* special characters */
};


# define IN6_IS_ADDR_V4MAPPED(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->s6_addr32[0] == 0                                                  \
      && __a->s6_addr32[1] == 0                                               \
      && __a->s6_addr32[2] == htonl (0xffff); }))

# define IN6_IS_ADDR_V4COMPAT(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->s6_addr32[0] == 0                                                  \
      && __a->s6_addr32[1] == 0                                               \
      && __a->s6_addr32[2] == 0                                               \
      && ntohl (__a->s6_addr32[3]) > 1; }))


#ifdef __cplusplus
extern "C" {
#endif
int     accept(int, struct sockaddr *, socklen_t *);
int     bind(int, const struct sockaddr *, socklen_t);
int     connect(int, const struct sockaddr *, socklen_t);
int     getpeername(int, struct sockaddr *, socklen_t *);
int     getsockname(int, struct sockaddr *, socklen_t *);
int     getsockopt(int, int, int, void *, socklen_t *);
int     listen(int, int);
ssize_t recv(int, void *, size_t, int);
ssize_t recvfrom(int, void *, size_t, int,
        struct sockaddr *, socklen_t *);
ssize_t recvmsg(int, struct msghdr *, int);
ssize_t send(int, const void *, size_t, int);
ssize_t sendmsg(int, const struct msghdr *, int);
ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *,
        socklen_t);
int     setsockopt(int, int, int, const void *, socklen_t);
int     shutdown(int, int);
int     socket(int, int, int);
int     sockatmark(int);
int     socketpair(int, int, int, int[2]);
int getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

void freeaddrinfo(struct addrinfo *res);

int gethostname(char *name, size_t len);
const char *inet_ntop(int af, const void *src,
                      char *dst, socklen_t size);
int inet_pton(int af, const char *src, void *dst);
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                       char *host, size_t hostlen,
                       char *serv, size_t servlen, int flags);
uint32_t htonl(uint32_t hostlong);
uint16_t htons(uint16_t hostshort);
uint32_t ntohl(uint32_t netlong);
uint16_t ntohs(uint16_t netshort);
ssize_t readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t writev(int fd, const struct iovec *iov, int iovcnt);



int tcgetattr(int fd, struct termios *termios_p);

int tcsetattr(int fd, int optional_actions,
              const struct termios *termios_p);

int tcsendbreak(int fd, int duration);

int tcdrain(int fd);

int tcflush(int fd, int queue_selector);

int tcflow(int fd, int action);

int getrlimit(int resource, struct rlimit *rlim);
int setrlimit(int resource, const struct rlimit *rlim);

int utime(const char *filename, const struct utimbuf *times);

int truncate(const char *path, off_t length);
int ftruncate(int fd, off_t length);
int lstat(const char *path, struct stat *buf);

struct statvfs {
    unsigned long  f_bsize;    /* filesystem block size */
    unsigned long  f_frsize;   /* fragment size */
    unsigned long f_blocks;   /* size of fs in f_frsize units */
    unsigned long f_bfree;    /* # free blocks */
    unsigned long f_bavail;   /* # free blocks for unprivileged users */
    unsigned long f_files;    /* # inodes */
    unsigned long f_ffree;    /* # free inodes */
    unsigned long     f_favail;   /* # free inodes for unprivileged users */
    unsigned long  f_fsid;     /* filesystem ID */
    unsigned long  f_flag;     /* mount flags */
    unsigned long  f_namemax;  /* maximum filename length */
};
int statvfs(const char *path, struct statvfs *buf);
int fstatvfs(int fd, struct statvfs *buf);

#include <dirent.h>
DIR *opendir(const char *name);
DIR *fdopendir(int fd);
struct dirent *readdir(DIR *dirp);
int closedir(DIR* d);
#ifdef __cplusplus
}
#endif