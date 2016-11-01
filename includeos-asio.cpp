 #include <includeos-asio.hh>
 #include <timers>
 #undef INADDR_ANY
 #include <net/inet4.hpp>
 #include <net/ip4/udp_socket.hpp>
 #include <reactor/scheduler.hh>
 using namespace net;
 void wake_scheduler();
 void sched_step();

 static const bool debug_net = true;
 net::Inet4& get_stack()
 {
   static net::Inet4& stack = net::Inet4::ifconfig<0>(10);
   static bool init = false;
   if (!init)
   {
     init = true;
     stack.network_config({ 10,0,0,42 },      // IP
                           { 255,255,255,0 },  // Netmask
                           { 10,0,0,1 },       // Gateway
                           { 8,8,8,8 });       // DNS
   }
   return stack;
 }
void schedule(std::function<void()> f, bool force_async = false)
{
  if (false && force_async)
  {
    new reactor::Thread("async", [f] { f();}, true);
    wake_scheduler();
  }
  else
  {
    new reactor::Thread("async", [f] { f();}, true);
    if (!reactor::scheduler().current())
      sched_step();
    //debug
    wake_scheduler();
    //f();
    //wake_scheduler();
    //sched_step();
  }
}

   IncludeOSUDPService::IncludeOSUDPService(boost::asio::io_service& io)
    : boost::asio::io_service::service(io)
    , stack(get_stack())
    {
      if (debug_net) printf("INIT SERVICE\n");
    }
  void IncludeOSUDPService::construct(IncludeOSUDPHandle handle)
  {
    handle.local_port = -1;
  }
  void IncludeOSUDPService::destroy(IncludeOSUDPHandle handle)
  {
  }
  void IncludeOSUDPService::shutdown_service() {}
  void IncludeOSUDPService::move_construct(IncludeOSUDPHandle& to, IncludeOSUDPHandle& from)
  {
    if (debug_net) printf("SOCKET MOVE\n");
    to.local_port = from.local_port;
    from.local_port = -1;
  }


  bool IncludeOSUDPService::is_open(IncludeOSUDPHandle const& h) const
  {
    return h.socket;
  }
  boost::system::error_code IncludeOSUDPService::close(IncludeOSUDPHandle& h, error_code& erc)
  {

  }
  int IncludeOSUDPService::native_handle(IncludeOSUDPHandle& h)
  {
    if (debug_net) printf("NH\n");
    return 0;
  }

  boost::system::error_code IncludeOSUDPService::cancel(IncludeOSUDPHandle& h, error_code& ec)
  {
    if (debug_net) printf("cancel\n");
    if (h.on_read)
    {
      auto handler = h.on_read;
      h.on_read = decltype(h.on_read)();
      h.on_read_buffer = nullptr;
      schedule([handler] {
          handler(boost::asio::error::operation_aborted, 0);
      }, true);
    }
    if (h.on_write)
    {
      auto handler = h.on_write;
      h.on_write = decltype(h.on_write)();
      schedule([handler] {
          handler(boost::asio::error::operation_aborted, 0);
      }, true);
    }
    ec = error_code();
    return ec;
  }
  size_t IncludeOSUDPService::available(IncludeOSUDPHandle& h)
  {
    return 0;
  }
  boost::system::error_code IncludeOSUDPService::bind(IncludeOSUDPHandle& h, boost::asio::ip::udp::endpoint ep, error_code& ec)
  {
    if (debug_net) printf("bind %d\n", ep.port());
    h.local_port = ep.port();
    ec = error_code();
    h.socket = &stack.udp().bind(h.local_port);
    h.socket->on_read(
      [&s=h](IP4::addr addr, UDP::port_t port, const char* data, size_t size) {
        if (debug_net) printf("ON_READ %d\n", size);
        auto ep = endpoint(boost::asio::ip::address_v4(::ntohl(addr.whole)), port);
        //if (debug_net) printf("GOT EP %s %d\n",
        //  ep.address().to_string().c_str(), ep.port());
        if (s.on_read)
        {
          if (s.on_read_endpoint)
            *s.on_read_endpoint = ep;
          size_t sz = std::min(size, s.on_read_buffer_size);
          memcpy(s.on_read_buffer, data, sz);
          s.on_read_buffer = nullptr;
          s.on_read_endpoint = nullptr;
          auto cb = s.on_read;
          s.on_read = RH();
          if (debug_net) printf("INVOKE CB %d\n", sz);
          schedule([cb, sz] {
              cb(error_code(), sz);
          });
        }
        else
        { // queue for later
          s.read_buffers.emplace_back(std::string(data, size), ep);
        }
    });
    return ec;
  }
  boost::system::error_code IncludeOSUDPService::shutdown(IncludeOSUDPHandle& h, boost::asio::socket_base::shutdown_type, error_code& ec)
  {
    ec = error_code();
    return ec;
  }
  IncludeOSUDPService::endpoint IncludeOSUDPService::local_endpoint(IncludeOSUDPHandle const& h, error_code& ec) const
  {
    ec = error_code();
    return endpoint(boost::asio::ip::address::from_string("0.0.0.0"), h.local_port);
  }
  IncludeOSUDPService::endpoint IncludeOSUDPService::remote_endpoint(IncludeOSUDPHandle const& h, error_code& ec) const
  {
    //std::cerr <<"remote_endpoint not implemented" << std::endl;
    return endpoint();
  }
  boost::system::error_code IncludeOSUDPService::connect(IncludeOSUDPHandle& h, endpoint, error_code& ec)
  {
    //std::cerr << "connect not implemented" << std::endl;
    ec = error_code();
    return ec;
  }

  void IncludeOSUDPService::async_receive_from(IncludeOSUDPHandle& h,
                                               boost::asio::mutable_buffer mb,
                                               endpoint& e,
                                               socket_base::message_flags f,
                                               RH rh)
  {
    if (debug_net) printf("ARF\n");
    auto bsz = boost::asio::buffer_size(mb);
    void* data = boost::asio::buffer_cast<char*>(mb);
    if (!h.read_buffers.empty())
    {
      auto sz = std::min(bsz, h.read_buffers.front().first.size());
      memcpy(data, h.read_buffers.front().first.data(), sz);
      if (&e)
        e = h.read_buffers.front().second;
      h.read_buffers.erase(h.read_buffers.begin());
      schedule( [rh, sz] {
            rh(error_code(), sz);
        }, true);
    }
    else
    {
      if (h.on_read)
        printf("Warning, multiple parallel calls to async_receive_from\n");
      h.on_read = rh;
      h.on_read_buffer = data;
      h.on_read_buffer_size = bsz;
      h.on_read_endpoint = &e;
    }
  }
  void IncludeOSUDPService::async_send_to(IncludeOSUDPHandle& h,
                                          boost::asio::const_buffer cb,
                                          endpoint e,
                                          socket_base::message_flags f, RH wh)
  {
    if (debug_net) printf("AST %s %d\n", e.address().to_string().c_str(), e.port());
    auto bsize = boost::asio::buffer_size(cb);
    const void* bdata = boost::asio::buffer_cast<const char*>(cb);
    if (debug_net) printf("backend sendto %d\n", (int)bsize);
    boost::asio::ip::address_v4 addr;
    if (e.address().is_v6())
    {
      auto v6 = e.address().to_v6();
      if (v6.is_v4_mapped())
      {
        addr = v6.to_v4();
      }
      else
        elle::err("V6 address not supported");
    }
    else
      addr = e.address().to_v4();
    if (debug_net) printf("ACVT %s %d %d conv %s\n", addr.to_string().c_str(), e.port(),
           (int)bsize, net::ip4::Addr(::ntohl(addr.to_ulong())).str().c_str());
    h.on_write = wh;
    h.socket->sendto(::ntohl(addr.to_ulong()), e.port(), bdata, bsize,
      [&h, wh, bsize] {
        if (debug_net) printf("sendto CB backend\n");
        if (!h.on_write)
        {
          if (debug_net) printf("on_write was reset, operation aborted\n");
          return;
        }
        h.on_write = decltype(h.on_write)();
        schedule([wh, bsize] {
            wh(error_code(), bsize);
            if (debug_net) printf("sendto CB backend wh called\n");
        });
      });
    /*
        Timers::oneshot(std::chrono::milliseconds(0), [wh, bsize](int) {
            wh(error_code(), bsize);
            if (debug_net) printf("sendto CB backend wh called\n");
            wake_scheduler();
        });
      });*/
  }

boost::asio::io_service::id IncludeOSUDPService::id;
boost::asio::io_service::id IncludeOSTCPService::id;
boost::asio::io_service::id IncludeOSTCPAcceptorService::id;
IncludeOSTCPAcceptorService::IncludeOSTCPAcceptorService(boost::asio::io_service& io)
: boost::asio::io_service::service(io)
, stack(get_stack())
{
}

void IncludeOSTCPAcceptorService::construct(IncludeOSTCPAcceptorHandle handle)
{
}
void IncludeOSTCPAcceptorService::destroy(IncludeOSTCPAcceptorHandle handle)
{
}
void IncludeOSTCPAcceptorService::shutdown_service()
{
}
void IncludeOSTCPAcceptorService::move_construct(
  IncludeOSTCPAcceptorHandle& to, IncludeOSTCPAcceptorHandle& from)
{
  to.listener = from.listener;
  to.endpoint = from.endpoint;
  to.target = from.target;
  to.cb = from.cb;
  from.listener = nullptr;
  from.target = nullptr;
  from.endpoint = endpoint();
}
bool IncludeOSTCPAcceptorService::is_open(
  IncludeOSTCPAcceptorHandle const& h) const
{
  return h.listener;
}
boost::system::error_code
IncludeOSTCPAcceptorService::close(IncludeOSTCPAcceptorHandle& h, error_code& ec)
{
  if (debug_net) printf("################## AS CLOSE\n");
  ec = error_code();
  if (h.listener)
    h.listener->close();
  return ec;
}
int IncludeOSTCPAcceptorService::native_handle(IncludeOSTCPAcceptorHandle& h)
{
  return 0;
}
boost::system::error_code
IncludeOSTCPAcceptorService::cancel(IncludeOSTCPAcceptorHandle& h, error_code& ec)
{
  if (debug_net) printf("AS CANCEL\n");
  if (h.cb)
  {
    auto handler = h.cb;
    h.cb = decltype(h.cb)();
    h.target = nullptr;
    h.target_endpoint = nullptr;
    schedule( [handler] {
      handler(boost::asio::error::operation_aborted);
    }, true);
  }
  ec = error_code();
  return ec;
}
boost::asio::ip::tcp::endpoint IncludeOSTCPAcceptorService::local_endpoint(
  IncludeOSTCPAcceptorHandle const& h, error_code& ec) const
{
  ec = error_code();
  return h.endpoint;
}
boost::system::error_code IncludeOSTCPAcceptorService::listen(IncludeOSTCPAcceptorHandle& h, size_t, error_code& ec)
{
  ec = error_code();
  return ec;
}

boost::system::error_code IncludeOSTCPAcceptorService::bind(
  IncludeOSTCPAcceptorHandle& h, endpoint ep, error_code& ec)
{
  h.endpoint = ep;
  h.listener = &stack.tcp().bind(ep.port());
  h.listener->on_connect([&h](net::tcp::Connection_ptr c) {
      if (debug_net) printf("on_connect %d\n", (int)!!h.cb);
      if (h.cb)
      {
        assert(h.target);
        h.target->assign(boost::asio::ip::tcp::v4(), &c);
        if (debug_net) printf("assigned\n");
        if (h.target_endpoint)
          *h.target_endpoint = endpoint(
            boost::asio::ip::address_v4(::ntohl(c->remote().address().whole)),
            c->remote().port());
        auto f = h.cb;
        h.cb = std::function<void(const error_code&)>();
        h.target = nullptr;
        h.target_endpoint = nullptr;
        if (debug_net) printf("signaling\n");
        schedule([f] { f(error_code());});
      }
      else
        h.inbounds.push_back(c);
  });
  ec = error_code();
  if (debug_net) printf("BOUND TO %d\n", (int)ep.port());
  return ec;
}
void IncludeOSTCPAcceptorService::async_accept(IncludeOSTCPAcceptorHandle& h,
  boost::asio::basic_socket<boost::asio::ip::tcp, IncludeOSTCPService>& tgt,
  endpoint* ep,
  AH ah)
{
  if (!h.inbounds.empty())
  {
    auto c = h.inbounds.front();
    h.inbounds.erase(h.inbounds.begin());
    tgt.assign(boost::asio::ip::tcp::v4(), &c);
    if (ep)
     *ep = endpoint(
       boost::asio::ip::address_v4(::ntohl(c->remote().address().whole)),
       c->remote().port());
    schedule([ah] { ah(error_code());}, true);
  }
  else
  {
    if (h.cb)
      if (debug_net) printf("#### multiple async_accept calls\n");
    h.target = &tgt;
    h.target_endpoint = ep;
    h.cb = ah;
  }
}

IncludeOSTCPService::IncludeOSTCPService(boost::asio::io_service& io)
: boost::asio::io_service::service(io)
, stack(get_stack())
{}

bool IncludeOSTCPService::is_open(IncludeOSTCPHandle const& h) const
{
  return !h.closed;
}
void IncludeOSTCPService::construct(IncludeOSTCPHandle handle)
{}
void IncludeOSTCPService::destroy(IncludeOSTCPHandle handle)
{}

boost::system::error_code IncludeOSTCPService::close(IncludeOSTCPHandle& h, error_code& ec)
{
  ec = error_code();
  if (h.closed || !h.socket)
  {
    if (debug_net) printf("not closing again\n");
    return ec;
  }
  if (debug_net) printf("closing\n");
  h.socket->close(); // will it call on_close?
  ec = error_code();
  return ec;
}
boost::system::error_code IncludeOSTCPService::cancel(IncludeOSTCPHandle& h, error_code& ec)
{
  ec = error_code();
  return ec;
}
boost::system::error_code IncludeOSTCPService::shutdown(IncludeOSTCPHandle& h, boost::asio::socket_base::shutdown_type, error_code& ec)
{
  if (debug_net) printf("shutdown\n");
  //close(h, ec);
  ec = error_code();
  return ec;
}


void IncludeOSTCPService::shutdown_service()
{
}
boost::asio::ip::tcp::endpoint
IncludeOSTCPService::local_endpoint(IncludeOSTCPHandle const& h, error_code& ec) const
{
  auto s = h.socket->local();
  return endpoint(boost::asio::ip::address_v4(::ntohl(s.address().whole)), s.port());
}
boost::asio::ip::tcp::endpoint
IncludeOSTCPService::remote_endpoint(IncludeOSTCPHandle const& h, error_code& ec) const
{
  auto s = h.socket->remote();
  return endpoint(boost::asio::ip::address_v4(::ntohl(s.address().whole)), s.port());
}

void IncludeOSTCPService::async_connect(IncludeOSTCPHandle& h, endpoint ep, CH cb)
{
  net::tcp::Socket s(net::ip4::Addr(ep.address().to_v4().to_ulong()), ep.port());
  stack.tcp().connect(s, [&h, cb](net::tcp::Connection_ptr c) {
      h.assign(c);
      schedule([cb] { cb(error_code());});
  });
}


void IncludeOSTCPService::async_receive(
  IncludeOSTCPHandle& h, boost::asio::mutable_buffer mb,
  socket_base::message_flags f, RH cb)
{
  if (h.closed)
  {
    if (debug_net) printf("async_receive on closed sock\n");
    schedule([cb] { cb(boost::asio::error::eof, 0);}, true);
    return;
  }
  if (h.on_read_buffer)
    printf("Warning, multiple // calls to async_receive!\n");
  auto mbs = boost::asio::buffer_size(mb);
  auto mbdata = boost::asio::buffer_cast<char*>(mb);
  if (!mbs || !mbdata)
    printf("####### null buffers not handled!\n");
  if (debug_net) printf("async_receive %d, buffered=%d\n", (int)mbs, (int)h.read_buffer.size());
  if (!h.read_buffer.empty())
  {
    auto rsz = std::min(mbs, h.read_buffer.size());
    memcpy(mbdata, h.read_buffer.data(), rsz);
    memmove((void*)h.read_buffer.data(), h.read_buffer.data()+rsz,
      h.read_buffer.size() - rsz);
    h.read_buffer.resize(h.read_buffer.size()-rsz);
    if (debug_net) printf("remaining in buffer: %d\n", (int)h.read_buffer.size());
    schedule([cb, rsz] { cb(error_code(), rsz);}, true);
  }
  else
  {
    if (h.on_read_buffer)
      printf("Warning, multiple // calls to async_receive!\n");
    h.on_read_buffer = mbdata;
    h.on_read_buffer_size = mbs;
    h.on_read = cb;
    h.source_buffer = mb;
    if (debug_net) printf("arming waiter=%d at %x\n", (int)mbs, (void*)h.on_read_buffer);
  }
}
static
void
flush_and_cont(int i, IncludeOSTCPHandle& h, size_t len,
  IncludeOSTCPService::RH wh)
{
  if (h.socket->sendq_size() || !h.socket->is_writable())
  {
    if (debug_net) printf("delaying on_write...\n");
    Timers::oneshot(std::chrono::milliseconds(1),
      [&h, len, wh] (int i) {
        flush_and_cont(i, h, len, wh);
      });
  }
  else
    schedule([wh, len] { wh(boost::system::error_code(), len);});
}

void IncludeOSTCPService::async_send(IncludeOSTCPHandle& h,
                                     boost::asio::const_buffer cb,
                                     socket_base::message_flags f, RH wh)
{
  if (h.closed)
  {
    if (debug_net) printf("async_send on closed sock\n");
    schedule([wh] { wh(boost::asio::error::eof, 0);}, true);
    return;
  }
  if (h.on_write)
    printf("###### async_send already running\n");
  auto mbs = boost::asio::buffer_size(cb);
  auto mbdata = boost::asio::buffer_cast<const char*>(cb);
  if (!mbs || !mbdata)
    printf("####### null buffers not handled!\n");
  h.on_write = wh;
  if (debug_net)
    printf("async_send %d bytes\n", (int)mbs);
  h.socket->write(mbdata, mbs, [&h, wh, cb](size_t len) {
  });

  h.on_write = decltype(h.on_write)();
  if (h.closed)
    if (debug_net) printf("write CB after close\n");
  if (debug_net)
    printf("async_send_callback with %d bytes\n", (int)mbs);
  Timers::oneshot(std::chrono::milliseconds(1), [wh, mbs](int) {
      schedule([wh, mbs] { wh(error_code(), mbs);});
  });
      /*Timers::oneshot(std::chrono::milliseconds(2),
        [&h, len, wh] (int i) {
          flush_and_cont(i, h, len, wh);
        });*/
      //flush_and_cont(0, h, len, wh);
      /*
      Timers::oneshot(std::chrono::milliseconds(10), [wh, len](int) {
          schedule([wh, len] { wh(error_code(), len);});
      });*/
      //schedule([wh, len] { reactor::sleep(1_sec); wh(error_code(), len);});
      if (debug_net)
        printf("async_send_callback exited\n");
      // });
}

IncludeOSTCPHandle::IncludeOSTCPHandle()
  : on_read_buffer(nullptr)
  , closed(false)
{}

void IncludeOSTCPHandle::assign(net::tcp::Connection_ptr c)
{
  socket = c;
  socket->on_read(65536, [this] (net::tcp::buffer_t sdata, size_t sz) {
      if (this->closed)
        if (debug_net) printf("Weird onread after close\n");
      if (debug_net) printf("on_read %d, buffered=%d waiter=%d at %x\n",
        (int)sz, (int)this->read_buffer.size(), (int)this->on_read_buffer_size,
        (void*)this->on_read_buffer);
      unsigned char* data = sdata.get();
      if (this->on_read_buffer)
      {
        if (!read_buffer.empty())
          printf("WARNING IMPOSSIBLE STATE\n");
        auto rsz = std::min(sz, this->on_read_buffer_size);
        memcpy(this->on_read_buffer, data, rsz);
        sz -= rsz;
        data = data + rsz;
        read_buffer.append((char*)data, (char*)data + sz);
        this->on_read_buffer = nullptr;
        this->on_read_buffer_size = 0;
        auto cb = this->on_read;
        this->on_read = decltype(this->on_read)();
        schedule([cb, rsz] {
            if (debug_net) printf("invoking on_read cb with %d\n", rsz);
            cb(boost::system::error_code(), rsz);
        });
      }
      else
        read_buffer.append((char*)data, (char*)data + sz);
      if (debug_net) printf("rb remain: %d\n", (int)read_buffer.size());
  });
  socket->on_close([this] () {
      if (debug_net) printf("ON_CLOSE\n");
      this->closed = true;
      if (this->on_read)
      {
        if (debug_net) printf("notifying reader\n");
        schedule([on_read=on_read] {
            on_read(boost::asio::error::eof, 0);
        });
        on_read = decltype(on_read)();
      }
      if (this->on_write)
      {
        if (debug_net) printf("notifying writer\n");
        schedule([on_write=on_write] {
            on_write(boost::asio::error::eof, 0);
        }, true);
        on_write = decltype(on_write)();
      }
      /*new reactor::Thread("holder", [socket=this->socket] {
          if (debug_net) printf("NOT releasing socket\n");
          new net::tcp::Connection_ptr(socket);
          reactor::sleep(1_sec);
      }, true);*/
      schedule([socket=this->socket] {
      });
      //new net::tcp::Connection_ptr(socket);
      this->socket.reset();
  });
}



 IncludeOSTimerImpl::IncludeOSTimerImpl()
 :timer_id(Timers::UNUSED_ID)
 {}
 IncludeOSTimerService::IncludeOSTimerService(boost::asio::io_service& io)
  : boost::asio::io_service::service(io)
  {
  }
  void IncludeOSTimerService::shutdown_service()
  {
  }
  void IncludeOSTimerService::construct(IncludeOSTimerImpl& mt)
  {
  }
  void IncludeOSTimerService::destroy(IncludeOSTimerImpl& mt)
  {
    error_code erc;
    this->cancel(mt, erc);
  }
  size_t IncludeOSTimerService::cancel(IncludeOSTimerImpl& mt, error_code& erc)
  {
    //if (debug_net) printf("canceling timer\n");
    erc = error_code();
    if (mt.timer_id != Timers::UNUSED_ID)
      Timers::stop(mt.timer_id);
    mt.timer_id =Timers::UNUSED_ID;
    for (auto const& wh: mt.listeners)
    {
      //wh(boost::asio::error::operation_aborted);;
      schedule([wh] { wh(boost::asio::error::operation_aborted);}, true);
    }
    size_t count = mt.listeners.size();
    mt.listeners.clear();
    return count;
  }
  IncludeOSTimerService::Time IncludeOSTimerService::expires_at(IncludeOSTimerImpl const& mt)
  {
    return mt.expiration;
  }
  size_t IncludeOSTimerService::expires_at(IncludeOSTimerImpl& mt, Time when, error_code& erc)
  {
    size_t res = cancel(mt, erc);
    mt.expiration = when;
    return res;
  }
  IncludeOSTimerService::Duration IncludeOSTimerService::expires_from_now(IncludeOSTimerImpl const& mt)
  {
    return TimeTraits::subtract(expires_at(mt), TimeTraits::now());
  }
  size_t IncludeOSTimerService::expires_from_now(IncludeOSTimerImpl& mt,
                          TimeTraits::duration_type d,
                          error_code& erc)
  {
    return expires_at(mt, TimeTraits::add(TimeTraits::now(), d), erc);
  }
  boost::system::error_code IncludeOSTimerService::wait(IncludeOSTimerImpl const& mt, error_code& erc)
  {
    //std::cerr << "WAIT not implemented" << std::endl;
    return error_code();
  }
  void IncludeOSTimerService::async_wait(IncludeOSTimerImpl& mt, WaitHandler cb)
  {
    auto now = TimeTraits::now();
    if (mt.expiration <= now)
    {
      //Timers::oneshot(std::chrono::milliseconds(0), [cb](int) { cb(error_code());});
      schedule([cb] { cb(error_code());}, true);
      return;
    }
    mt.listeners.push_back(cb);
    if (mt.timer_id == Timers::UNUSED_ID)
    {
      auto delay = mt.expiration - now;
      auto cdelay = std::chrono::microseconds(delay.total_microseconds());
      //std::cerr <<"timer in " << fdelay << std::endl;
      mt.timer_id = Timers::oneshot(cdelay, [&mt](int) {
          auto cbs = std::move(mt.listeners);
          mt.listeners.clear();
          mt.timer_id = Timers::UNUSED_ID;
          for (auto& cb: cbs)
             schedule([cb] { cb(error_code());});
      });
    }
  }

boost::asio::io_service::id IncludeOSTimerService::id;