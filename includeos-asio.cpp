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