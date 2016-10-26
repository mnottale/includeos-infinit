 #include <includeos-asio.hh>
 #include <timers>
 #undef INADDR_ANY
 #include <net/inet4.hpp>
 #include <net/ip4/udp_socket.hpp>
 #include <reactor/scheduler.hh>
 using namespace net;
 void wake_scheduler();
 
 
   IncludeOSUDPService::IncludeOSUDPService(boost::asio::io_service& io)
    : boost::asio::io_service::service(io)
    , stack(net::Inet4::ifconfig<0>(10))
    {
      printf("INIT SERVICE\n");
      stack.network_config({ 10,0,0,42 },      // IP
                           { 255,255,255,0 },  // Netmask
                           { 10,0,0,1 },       // Gateway
                           { 8,8,8,8 });       // DNS
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
    printf("SOCKET MOVE\n");
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
    printf("NH\n");
    return 0;
  }

  boost::system::error_code IncludeOSUDPService::cancel(IncludeOSUDPHandle& h, error_code& ec)
  {
    printf("cancel\n");
    ec = error_code();
    return ec;
  }
  size_t IncludeOSUDPService::available(IncludeOSUDPHandle& h)
  {
    return 0;
  }
  boost::system::error_code IncludeOSUDPService::bind(IncludeOSUDPHandle& h, boost::asio::ip::udp::endpoint ep, error_code& ec)
  {
    printf("bind %d\n", ep.port());
    h.local_port = ep.port();
    ec = error_code();
    h.socket = &stack.udp().bind(h.local_port);
    h.socket->on_read(
      [&s=h](IP4::addr addr, UDP::port_t port, const char* data, size_t size) {
        printf("ON_READ %d\n", size);
        auto ep = endpoint(boost::asio::ip::address_v4(addr.whole), port);
        //printf("GOT EP %s %d\n",
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
          printf("INVOKE CB %d\n", sz);
          new reactor::Thread("recvfrom_cb", [cb, sz] {
              cb(error_code(), sz);
          }, true);
          wake_scheduler();
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
    printf("ARF\n");
    auto bsz = boost::asio::buffer_size(mb);
    void* data = boost::asio::buffer_cast<char*>(mb);
    if (!h.read_buffers.empty())
    {
      auto sz = std::min(bsz, h.read_buffers.front().first.size());
      memcpy(data, h.read_buffers.front().first.data(), sz);
      if (&e)
        e = h.read_buffers.front().second;
      h.read_buffers.erase(h.read_buffers.begin());
      new reactor::Thread("recvfrom_direct_cb", [rh, sz] {
            rh(error_code(), sz);
        }, true);
      wake_scheduler();
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
    printf("AST %s %d\n", e.address().to_string().c_str(), e.port());
    auto bsize = boost::asio::buffer_size(cb);
    const void* bdata = boost::asio::buffer_cast<const char*>(cb);
    printf("backend sendto %d\n", (int)bsize);
    std::string addr;
    if (e.address().is_v6())
    {
      auto v6 = e.address().to_v6();
      if (v6.is_v4_mapped())
        addr = v6.to_v4().to_string();
      else
        elle::err("V6 address not supported");
    }
    else
      addr = e.address().to_v4().to_string();
    printf("ACVT %s %d %d\n", addr.c_str(), e.port(), (int)bsize);
    h.socket->sendto(addr, e.port(), bdata, bsize,
      [wh, bsize] {
        printf("sendto CB backend\n");
        new reactor::Thread("sendto_cb", [wh, bsize] {
            wh(error_code(), bsize);
            printf("sendto CB backend wh called\n");
        }, true);
        wake_scheduler();
      });
    /*
        Timers::oneshot(std::chrono::milliseconds(0), [wh, bsize](int) {
            wh(error_code(), bsize);
            printf("sendto CB backend wh called\n");
            wake_scheduler();
        });
      });*/
  }

boost::asio::io_service::id IncludeOSUDPService::id;
boost::asio::io_service::id IncludeOSTCPService::id;
boost::asio::io_service::id IncludeOSTCPAcceptorService::id;
IncludeOSTCPAcceptorService::IncludeOSTCPAcceptorService(boost::asio::io_service& io)
: boost::asio::io_service::service(io)
, stack(net::Inet4::stack<0>())
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
      if (h.cb)
      {
        assert(h.target);
        h.target->assign(boost::asio::ip::tcp::v4(), c.get());
        if (h.target_endpoint)
          *h.target_endpoint = endpoint(
            boost::asio::ip::address_v4(c->remote().address().whole),
            c->remote().port());
        auto f = h.cb;
        h.cb = std::function<void(const error_code&)>();
        h.target = nullptr;
        new reactor::Thread("connect_cb", [f] { f(error_code());}, true);
        wake_scheduler();
      }
      else
        h.inbounds.push_back(c);
  });
  ec = error_code();
  printf("BOUND TO %d\n", (int)ep.port());
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
    tgt.assign(boost::asio::ip::tcp::v4(), c.get());
    if (ep)
     *ep = endpoint(
       boost::asio::ip::address_v4(c->remote().address().whole),
       c->remote().port());
    new reactor::Thread("connect_direct_cb", [ah] { ah(error_code());}, true);
    wake_scheduler();
  }
  else
  {
    h.target = &tgt;
    h.target_endpoint = ep;
    h.cb = ah;
  }
}

IncludeOSTCPService::IncludeOSTCPService(boost::asio::io_service& io)
: boost::asio::io_service::service(io)
, stack(net::Inet4::stack<0>())
{}

bool IncludeOSTCPService::is_open(IncludeOSTCPHandle const& h) const
{
  return true;
}
void IncludeOSTCPService::construct(IncludeOSTCPHandle handle)
{}
void IncludeOSTCPService::destroy(IncludeOSTCPHandle handle)
{}

boost::system::error_code IncludeOSTCPService::close(IncludeOSTCPHandle& h, error_code& ec)
{
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
  return endpoint(boost::asio::ip::address_v4(s.address().whole), s.port());
}
boost::asio::ip::tcp::endpoint
IncludeOSTCPService::remote_endpoint(IncludeOSTCPHandle const& h, error_code& ec) const
{
  auto s = h.socket->remote();
  return endpoint(boost::asio::ip::address_v4(s.address().whole), s.port());
}

void IncludeOSTCPService::async_connect(IncludeOSTCPHandle& h, endpoint ep, CH cb)
{
  net::tcp::Socket s(net::ip4::Addr(ep.address().to_v4().to_ulong()), ep.port());
  stack.tcp().connect(s, [&h, cb](net::tcp::Connection_ptr c) {
      h.assign(c);
      new reactor::Thread("connect", [cb] { cb(error_code());}, true);
      wake_scheduler();
  });
}
 
 
void IncludeOSTCPService::async_receive(
  IncludeOSTCPHandle& h, boost::asio::mutable_buffer mb,
  socket_base::message_flags f, RH cb)
{
  if (h.closed)
  {
    new reactor::Thread("closed", [cb] { cb(boost::asio::error::eof, 0);}, true);
    return;
  }
  if (h.on_read_buffer)
    printf("Warning, multiple // calls to async_receive!\n");
  auto mbs = boost::asio::buffer_size(mb);
  auto mbdata = boost::asio::buffer_cast<char*>(mb);
  printf("async_receive %d, buffered=%d\n", (int)mbs, (int)h.read_buffer.size());
  if (!h.read_buffer.empty())
  {
    auto rsz = std::min(mbs, h.read_buffer.size());
    memcpy(mbdata, h.read_buffer.data(), rsz);
    memmove((void*)h.read_buffer.data(), h.read_buffer.data()+rsz,
      h.read_buffer.size() - rsz);
    h.read_buffer.resize(h.read_buffer.size()-rsz);
    printf("remaining in buffer: %d\n", (int)h.read_buffer.size());
    new reactor::Thread("onread", [cb, rsz] { cb(error_code(), rsz);}, true);
    wake_scheduler();
  }
  else
  {
    if (h.on_read_buffer)
      printf("Warning, multiple // calls to async_receive!\n");
    h.on_read_buffer = mbdata;
    h.on_read_buffer_size = mbs;
    h.on_read = cb;
    printf("arming waiter=%d\n", (int)mbs);
  }
}
void IncludeOSTCPService::async_send(IncludeOSTCPHandle& h,
                                     boost::asio::const_buffer cb,
                                     socket_base::message_flags f, RH wh)
{
  if (h.closed)
  {
    new reactor::Thread("closed", [wh] { wh(boost::asio::error::eof, 0);}, true);
    return;
  }
  auto mbs = boost::asio::buffer_size(cb);
  auto mbdata = boost::asio::buffer_cast<const char*>(cb);
  h.on_write = wh;
  h.socket->write(mbdata, mbs, [&h, wh](size_t len) {
      h.on_write = decltype(h.on_write)();
      new reactor::Thread("async_send", [wh, len] { wh(error_code(), len);}, true);
      wake_scheduler();
  });
}
 
 
 
void IncludeOSTCPHandle::assign(net::tcp::Connection_ptr c)
{
  socket = c;
  socket->on_read(4096, [this] (net::tcp::buffer_t sdata, size_t sz) {
      printf("on_read %d, buffered=%d waiter=%d\n",
        (int)sz, (int)this->read_buffer.size(), (int)this->on_read_buffer_size);
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
        new reactor::Thread("on_read", [cb, rsz] { cb(boost::system::error_code(), rsz);}, true);
        wake_scheduler();
      }
      else
        read_buffer.append((char*)data, (char*)data + sz);
      printf("rb remain: %d\n", (int)read_buffer.size());
  });
  socket->on_close([this] () {
      printf("ON_CLOSE\n");
      this->closed = true;
      if (this->on_read)
      {
        on_read(boost::asio::error::eof, 0);
        on_read = decltype(on_read)();
      }
      if (this->on_write)
      {
        on_write(boost::asio::error::eof, 0);
        on_write = decltype(on_write)();
      }
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
    erc = error_code();
    if (mt.timer_id != Timers::UNUSED_ID)
      Timers::stop(mt.timer_id);
    mt.timer_id =Timers::UNUSED_ID;
    for (auto const& wh: mt.listeners)
    {
      wh(boost::asio::error::operation_aborted);;
    }
    size_t count = mt.listeners.size();
    mt.listeners.clear();
    wake_scheduler();
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
      Timers::oneshot(std::chrono::milliseconds(0), [cb](int) { cb(error_code());});
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
            cb(error_code());
          wake_scheduler();
      });
    }
  }

boost::asio::io_service::id IncludeOSTimerService::id;