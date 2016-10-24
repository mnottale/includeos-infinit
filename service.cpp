// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <service>
#include <timers>
#include <cstdio>

#include <elle/log.hh>
ELLE_LOG_COMPONENT("foo");
#include <reactor/scheduler.hh>
#include <reactor/mutex.hh>
#include <reactor/backend/boost_context/backend.hh>
#include <reactor/network/udp-socket.hh>
#include <reactor/network/buffer.hh>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <infinit/model/doughnut/Doughnut.hh>
#include <infinit/model/doughnut/consensus/Paxos.hh>
#include <infinit/overlay/kelips/Kelips.hh>
#include <infinit/storage/Memory.hh>





reactor::Scheduler* sched = 0;
bool scheduler_sleeping = false;
void sched_step()
{
  printf("sched step %ld\n", sched);
  scheduler_sleeping = false; 
  while (sched->step())
    ;
  scheduler_sleeping = true;
  //Timers::oneshot(std::chrono::milliseconds(100), [](int) { sched_step();});
}

void wake_scheduler()
{
  if (scheduler_sleeping)
  {
    scheduler_sleeping = false;
    Timers::oneshot(std::chrono::milliseconds(0), [](int) { sched_step();});
  }
}

static const char userkey[] = "{\"rsa\" : \"MIIEowIBAAKCAQEAxAtcxUwkLs1m2cDOe7WtFxAr2BR4rsDLC9UlMlW1e/DJi4ShgGI8mx7pe7i1EvpYc0H3vQ/c01Q0CppZcZCRPFA3yhpYVjsPYDktesXG4OtHHGe5KDo+U+nFBY6lcBFqeKTZdKmFHNaNy+JhOHLjPPrJrqamsac/S1B8GGPm9Z3hqmfNkvOalgXfao+KLLnJLB48in6QvUMlNIplzI8ZM5/2D8jBm12jybrkaWNmD0Dq1Bx+PGwGgpeR29un09pyg4a/7AsZeJdO0VXKDZUpRR4SHaXFMkG3yiOO2iR67pOkteq1VtXEQPLaIl9aN5fo9NcQQIKrhce3gpO17lA9owIDAQABAoIBAQCvIPtZ4N/9003Kvnt2deBPVwnjuL3qVp3MTzcwVPKP6pURBoWDe75qUF4BQQq5DlzPcaHPCgmZ24G16xZ15dBoUbzU1V4OgioFKm7fWyiDqopW7K2yKv2c1ptDkJ9nkpdLePAtUHZyQZRgCzYQSEmJIvviAkutLhvTuu1wmGYtCLG9CRQJ2i0M1e3y54JVavr/JX0VRZtqvWkN6s9pcXKfz86buNEI8jU0EPq2gO0YCT9eahdIaZtkn4vmRluAMnYfs+Cacc8e8ZvglvH+fDvLCSlrK96/tG0dRIAzfN+A8PJ82ojkyhfBVSKFHYK/8GyIrEtBdU0v/bOTwM8gvS35AoGBAOV8ZdXyscSIe+tmpHiEIf3+R5AdRAAbd66tyjiTg1WyFpKsOq7O9NoxxCcw/5Jc1IfGtZ7FmjWCp5coIbcRkOXza84Q+apGzMK7zeWfeCsbs55mQ5aRDnHYx4/G0lonoPQNv7RVxiaEzm+VgeXvqHBZYKUscf8A9LpMhjOwlML1AoGBANqx2ZOH3YN7qUIhSaZIYiFJKnU7J2aYfqqEMpdmVazbzyy9qnLwE5AUBoDy/OrGuW/D6YNeT6ISJUfBF7JU71NeAdXY3wcYN2gOeD1mUNNdbMs2c/vY0gDQ6USG9gaaWmrgzrpTop2ILFKc6+b4gAfaL3Zz7yrbrgCVuvCCdg83AoGAaasjNSXAZ0+1R8qGlxu4jzzj9N8U7bu4G03Y3L5H7lDHhhgaGV4gbswVlzo/pERsdGyyOn6gqF0WEEshYyuKfefdTxCP9bEOHejeQQpyCd+CkMBkBNOcRB3enjydpXez7EzcZgxM5nWmnMjJ/HejJsBw+P2DLDljdtk/vlNj3HUCgYAqplalU/DaTIqU0AMZ/7HLhgZWuIOVmZXSUVfAeP+qZ2++7PpJ0hIungkqqriyXLEbX9yxdvoWxG0q0jh52eCWpJW9C79rFcjwbSn753FJ10V5WBREgGNsL1HewGdIoF+TymXmpprnGAB02A+Vis8FOQLamf+BnzgO+yRq9TZq/wKBgFhGMzVF24B13mZBiuHafBgtypl0NlkaABQMKP/YQxMe50UbowX8OpWQh4/vz+Zp5kWWSe8FnRMyIw0A5g4+oFXBSl6NQsYLqoY83vDRGoN4sMMJboJa5RzoPk8uIPmXS54KgmNGlSgWUmSkNB8sNX9DI87zfJk9wDmsuvZO8TN8\"}";
void init_infinit()
{
  reactor::sleep(1_sec);
  /*while (true)
  {
    printf("CANARD\n");
    reactor::sleep(500_ms);
  }*/
  
  printf("infinit starter thread\n");
  namespace dht = infinit::model::doughnut;
  auto priv = elle::serialization::json::deserialize
    <infinit::cryptography::rsa::PrivateKey>(elle::Buffer(userkey), false);
  auto pub = infinit::cryptography::rsa::PublicKey(priv);
  printf("keypair\n");
  auto keys = std::make_shared<infinit::cryptography::rsa::KeyPair>(
    pub, priv);
  auto consensus = [&] (dht::Doughnut& dht)
  {
   return elle::make_unique<dht::consensus::Paxos>(
     dht::consensus::doughnut = dht,
     dht::consensus::replication_factor = 1);
  };
  printf("passport\n");
  auto passport = new dht::Passport(keys->K(), "network-", *keys);
  infinit::overlay::kelips::Configuration conf;
  auto overlay = [&](
    dht::Doughnut& d,
    std::shared_ptr<dht::Local> local)
      -> std::unique_ptr<infinit::overlay::Overlay> {
    return std::unique_ptr<infinit::overlay::Overlay>(
      new infinit::overlay::kelips::Node(conf, std::move(local),&d));
  };
  printf("storage\n");
  auto storage = std::unique_ptr<infinit::storage::Storage>(new infinit::storage::Memory());
  printf("dht\n");
  auto d = new dht::Doughnut(
    dht::id = infinit::model::Address::random(),
    dht::keys = keys,
    dht::owner = keys->public_key(),
    dht::passport = *passport,
    dht::consensus_builder = consensus,
    dht::overlay_builder = overlay,
    dht::port = 6666,
    dht::storage = std::move(storage),
    dht::protocol = dht::Protocol::all
    );
  printf("DONE");
}

void init_tcp()
{
  reactor::sleep(1_sec);
  auto s = new reactor::network::TCPServer();
  s->listen(4444);
  while (true)
  {
    auto tt = s->accept();
    ELLE_LOG("new connection %s", tt->peer());
    new reactor::Thread("hs", [t=tt.release()] {
        try
        {
          reactor::sleep(3_sec);
          while (true)
          {
            auto data = t->read_some(1024);
            t->write(data);
            reactor::sleep(2_sec);
          }
        }
        catch(elle::Error const&e)
        {
          ELLE_LOG("tcp end: %s", e);
        }
    }, true);
  }
}
void init_udp()
{
  printf("INIT UDP\n");
  auto u = new reactor::network::UDPSocket(*sched);
  u->bind(boost::asio::ip::udp::endpoint(
    boost::asio::ip::address_v4(), 5555));
  while (true)
  {
    boost::asio::ip::udp::endpoint endpoint;
    char buffer[4096];
    printf("RECVFROM\n");
    auto sz = u->receive_from(reactor::network::Buffer(buffer, 4096), endpoint);
    printf("SENDTO %d\n", sz);
    u->send_to(reactor::network::Buffer(buffer, sz), endpoint);
    printf("SENDTO RETURNED\n");
  }
}
class StaticInit
{
public:
  NAMED_ARGUMENT(nacanard);
  StaticInit()
  {
    printf("STATIC INIT\n");
    write(1, "SINIT\n", 6);
    write(2, "TINIT\n", 6);
  }
  
};
// OK
NAMED_ARGUMENT_DEFINE(nacanard, StaticInit);
//extern "C" void __cxx_global_var_init64() {}
//extern "C" void __cxx_global_var_init57() {}
extern "C" void __cxx_global_var_init();
extern "C" void __do_global_ctors_aux();
extern "C" void _init();
StaticInit test;
void Service::start(const std::string&)
{
  setenv("ELLE_LOG_LEVEL", "DUMP", 1);
  setenv("INFINIT_RDV", "", 1);
  //setenv("INFINIT_NO_IPV6", "1", 1);
  printf("Hello world - OS included!\n");
  write(1, "COIN\n", 5);
  //__cxx_global_var_init();
  //__do_global_ctors_aux();
  //_init(); // causes exit
  ELLE_LOG("canard");
  ELLE_TRACE("trace level");
  // OK
  reactor::backend::boost_context::Backend b;
  // OK
  boost::filesystem::path p("/tmp/coin");
  boost::filesystem::exists(p);
  std::cerr << "canard" << std::endl;
  std::cout << "coincoin" << std::endl;
  std::cin.good();
  // ok
  //boost::asio::io_service io;
  // runtime crash
  //boost::asio::ip::tcp::socket s(io);
  // BAD // passes with non debug build
 //reactor::Mutex m;
  // OK
  // exception.o
  sched = new reactor::Scheduler();
  auto t = new reactor::Thread(*sched, "init_infinit", init_infinit, true);
  printf("Hello world: arming... !\n");
  Timers::oneshot(std::chrono::milliseconds(100), [](int) { sched_step();});
  
  new reactor::Thread(*sched, "init_udp", [] {init_udp();}, true);
  new reactor::Thread(*sched, "init_tcp", [] {init_tcp();}, true);
}

#define NS_INADDRSZ 4
static int
inet_pton4(const char* src, u_char* dst)
{
        int saw_digit, octets, ch;
        u_char tmp[NS_INADDRSZ], *tp;

        saw_digit = 0;
        octets = 0;
        *(tp = tmp) = 0;
        while ((ch = *src++) != '\0') {

                if (ch >= '0' && ch <= '9') {
                        u_int neww = *tp * 10 + (ch - '0');

                        if (saw_digit && *tp == 0)
                                return (0);
                        if (neww > 255)
                                return (0);
                        *tp = neww;
                        if (! saw_digit) {
                                if (++octets > 4)
                                        return (0);
                                saw_digit = 1;
                        }
                } else if (ch == '.' && saw_digit) {
                        if (octets == 4)
                                return (0);
                        *++tp = 0;
                        saw_digit = 0;
                } else
                        return (0);
        }
        if (octets < 4)
                return (0);
        memcpy(dst, tmp, NS_INADDRSZ);
        return (1);
}

#define NS_IN6ADDRSZ	16
#define NS_INT16SZ	2

static int
inet_pton6(const char*src, unsigned char*dst)
{
        static const char xdigits[] = "0123456789abcdef";
        u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
        const char *curtok;
        int ch, saw_xdigit;
        u_int val;

        tp = (unsigned char*)memset(tmp, '\0', NS_IN6ADDRSZ);
        endp = tp + NS_IN6ADDRSZ;
        colonp = NULL;
        /* Leading :: requires some special handling. */
        if (*src == ':')
                if (*++src != ':')
                        return (0);
        curtok = src;
        saw_xdigit = 0;
        val = 0;
        while ((ch = tolower (*src++)) != '\0') {
                const char *pch;

                pch = strchr(xdigits, ch);
                if (pch != NULL) {
                        val <<= 4;
                        val |= (pch - xdigits);
                        if (val > 0xffff)
                                return (0);
                        saw_xdigit = 1;
                        continue;
                }
                if (ch == ':') {
                        curtok = src;
                        if (!saw_xdigit) {
                                if (colonp)
                                        return (0);
                                colonp = tp;
                                continue;
                        } else if (*src == '\0') {
                                return (0);
                        }
                        if (tp + NS_INT16SZ > endp)
                                return (0);
                        *tp++ = (u_char) (val >> 8) & 0xff;
                        *tp++ = (u_char) val & 0xff;
                        saw_xdigit = 0;
                        val = 0;
                        continue;
                }
                if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
                    inet_pton4(curtok, tp) > 0) {
                        tp += NS_INADDRSZ;
                        saw_xdigit = 0;
                        break;  /* '\0' was seen by inet_pton4(). */
                }
                return (0);
        }
        if (saw_xdigit) {
                if (tp + NS_INT16SZ > endp)
                        return (0);
                *tp++ = (u_char) (val >> 8) & 0xff;
                *tp++ = (u_char) val & 0xff;
        }
        if (colonp != NULL) {
                /*
                 * Since some memmove()'s erroneously fail to handle
                 * overlapping regions, we'll do the shift by hand.
                 */
                const int n = tp - colonp;
                int i;

                if (tp == endp)
                        return (0);
                for (i = 1; i <= n; i++) {
                        endp[- i] = colonp[n - i];
                        colonp[n - i] = 0;
                }
                tp = endp;
        }
        if (tp != endp)
                return (0);
        memcpy(dst, tmp, NS_IN6ADDRSZ);
        return (1);
}
  
        
extern "C" int
inet_pton(int af, const char*src, void* dst)
{
        switch (af) {
        case AF_INET:
                return (inet_pton4(src, (unsigned char*)dst));
        case AF_INET6:
                return (inet_pton6(src, (unsigned char*)dst));
        default:
        //        __set_errno (EAFNOSUPPORT);
                return (-1);
        }
        /* NOTREACHED */
}
extern "C"  const char *inet_ntop(int af, const void *src,
                             char *dst, socklen_t size);
static const char *
inet_ntop6(const unsigned char *src, char* dst, socklen_t size)
{
        /*
         * Note that int32_t and int16_t need only be "at least" large enough
         * to contain a value of the specified size.  On some systems, like
         * Crays, there is no such thing as an integer variable with 16 bits.
         * Keep this in mind if you think this function should have been coded
         * to use pointer overlays.  All the world's not a VAX.
         */
        char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
        struct { int base, len; } best, cur;
        u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
        int i;

        /*
         * Preprocess:
         *      Copy the input (bytewise) array into a wordwise array.
         *      Find the longest run of 0x00's in src[] for :: shorthanding.
         */
        memset(words, '\0', sizeof words);
        for (i = 0; i < NS_IN6ADDRSZ; i += 2)
                words[i / 2] = (src[i] << 8) | src[i + 1];
        best.base = -1;
        cur.base = -1;
        best.len = 0;
        cur.len = 0;
        for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
                if (words[i] == 0) {
                        if (cur.base == -1)
                                cur.base = i, cur.len = 1;
                        else
                                cur.len++;
                } else {
                        if (cur.base != -1) {
                                if (best.base == -1 || cur.len > best.len)
                                        best = cur;
                                cur.base = -1;
                        }
                }
        }
        if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                        best = cur;
        }
        if (best.base != -1 && best.len < 2)
                best.base = -1;

        /*
         * Format the result.
         */
        tp = tmp;
        for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
                /* Are we inside the best run of 0x00's? */
                if (best.base != -1 && i >= best.base &&
                    i < (best.base + best.len)) {
                        if (i == best.base)
                                *tp++ = ':';
                        continue;
                }
                /* Are we following an initial run of 0x00s or any real hex? */
                if (i != 0)
                        *tp++ = ':';
                /* Is this address an encapsulated IPv4? */
                if (i == 6 && best.base == 0 &&
                    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
                        if (!inet_ntop(AF_INET, src+12, tp, sizeof tmp - (tp - tmp)))
                                return (NULL);
                        tp += strlen(tp);
                        break;
                }
                tp += sprintf(tp, "%x", words[i]);
        }
        /* Was it a trailing run of 0x00's? */
        if (best.base != -1 && (best.base + best.len) ==
            (NS_IN6ADDRSZ / NS_INT16SZ))
                *tp++ = ':';
        *tp++ = '\0';

        /*
         * Check for overflow, copy, and we're done.
         */
        if ((socklen_t)(tp - tmp) > size) {
                //__set_errno (ENOSPC);
                return (NULL);
        }
        return strcpy(dst, tmp);
}


extern "C"  const char *inet_ntop(int af, const void *src,
                             char *dst, socklen_t size)
{
  if (af == AF_INET6)
    return inet_ntop6((const unsigned char*)src, dst, size);
  const unsigned char* csrc = (const unsigned char*)src;
  sprintf(dst, "%d.%d.%d.%d",
    (unsigned int)csrc[0],
    (unsigned int)csrc[1],
    (unsigned int)csrc[2],
    (unsigned int)csrc[3]);
  printf("ntop: %s\n", dst);
  return dst;
}

extern "C" int aainet_pton(int af, const char *src, void *dst)
{
  printf("inet_pton %s\n", src);
  unsigned char* cdst = (unsigned char*)dst;
  
  return 1;
  /*
  std::vector<std::string> elems;
  boost::algorithm::split(elems, src, boost::is_any_of("."));
  unsigned char* cdst = (unsigned char*)dst;
  for (int i=0; i<4; ++i)
    cdst[i] = std::stoi(elems[i]);
  return 1;*/
}