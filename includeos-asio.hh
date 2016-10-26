#ifndef INCLUDEOS_ASIO_HH
# define INCLUDEOS_ASIO_HH
#include <boost/asio.hpp>


namespace net {
  class Inet4;
  class UDPSocket;
  class TCP;
  namespace tcp {
    class Connection;
    class Socket;
    class Listener;
    using Connection_ptr = std::shared_ptr<Connection>;
  }
}
class IncludeOSUDPHandle
{
public:
  IncludeOSUDPHandle()
   : local_port(-1)
   , socket(0)
   , on_read_endpoint(nullptr)
   , on_read_buffer(nullptr)               
  {}
  IncludeOSUDPHandle(IncludeOSUDPHandle const& b) = default;
  IncludeOSUDPHandle(IncludeOSUDPHandle&& b) = default;
  int local_port;
  net::UDPSocket* socket;
  std::vector<std::pair<std::string, boost::asio::ip::udp::endpoint>> read_buffers;
  boost::asio::ip::udp::endpoint* on_read_endpoint;
  void* on_read_buffer;
  size_t on_read_buffer_size;
  std::function<void(const boost::system::error_code& ec, std::size_t)> on_read;
};

class IncludeOSUDPService: public boost::asio::io_service::service
{
public:
  static boost::asio::io_service::id id;
  typedef IncludeOSUDPHandle implementation_type;
  typedef int native_handle_type;
  typedef boost::asio::ip::udp::endpoint endpoint;
  typedef boost::system::error_code error_code;
  typedef boost::asio::socket_base socket_base;
  typedef boost::asio::const_buffer const_buffer;
  typedef std::function<void(const error_code& ec, std::size_t)> RH;
  IncludeOSUDPService(boost::asio::io_service& io);
  void construct(IncludeOSUDPHandle handle);
  void destroy(IncludeOSUDPHandle handle);
  void shutdown_service() override;
  void move_construct(IncludeOSUDPHandle& to, IncludeOSUDPHandle& from);
  template<typename P>
  error_code open(IncludeOSUDPHandle&, P, error_code& ec)
  {
    ec = error_code();
    return ec;
  }
  template<typename P>
  error_code assign(IncludeOSUDPHandle& s, P, IncludeOSUDPHandle& n, error_code& ec)
  {
    s.local_port = n.local_port;
    ec = error_code();
    return ec;
  }
  bool is_open(IncludeOSUDPHandle const& h) const;
  error_code close(IncludeOSUDPHandle& h, error_code& ec);
  int native_handle(IncludeOSUDPHandle& h);
  error_code cancel(IncludeOSUDPHandle& h, error_code& ec);
  size_t available(IncludeOSUDPHandle& h);
  error_code bind(IncludeOSUDPHandle& h, boost::asio::ip::udp::endpoint ep, error_code& ec);
  error_code shutdown(IncludeOSUDPHandle& h, boost::asio::socket_base::shutdown_type, error_code& ec);
  endpoint local_endpoint(IncludeOSUDPHandle const& h, error_code& ec) const;
  endpoint remote_endpoint(IncludeOSUDPHandle const& h, error_code& ec) const;
  error_code connect(IncludeOSUDPHandle& h, endpoint, error_code& ec);
  template<typename CB>
  void async_connect(IncludeOSUDPHandle&, endpoint, CB)
  {
    std::cerr << "async_connect not implemented" << std::endl;
  }
  template<typename ...Args>
  void async_receive(Args...args)
  {
    std::cerr << "async_receive not implemented" << std::endl;
  }
  template<typename ...Args>
  void async_send(Args...args)
  {
    std::cerr << "async_send not implemented" << std::endl;
  }
  void async_receive_from(IncludeOSUDPHandle& b, boost::asio::mutable_buffer mb,
                          endpoint& e, socket_base::message_flags f,
                          RH cb);
  void async_send_to(IncludeOSUDPHandle& b, boost::asio::const_buffer cb, endpoint e,
                     socket_base::message_flags f, RH wh);
  net::Inet4& stack;
};

typedef boost::asio::basic_datagram_socket<boost::asio::ip::udp, IncludeOSUDPService>
IncludeOSUDPSocket;


class IncludeOSTCPHandle
{
public:
  IncludeOSTCPHandle()
   : on_read_buffer(nullptr)
   , closed(false)
  {}
  IncludeOSTCPHandle(IncludeOSTCPHandle const& b) = default;
  IncludeOSTCPHandle(IncludeOSTCPHandle&& b) = default;
  void assign(net::tcp::Connection_ptr c);
  net::tcp::Connection_ptr socket;
  std::string read_buffer;
  void* on_read_buffer;
  size_t on_read_buffer_size;
  std::function<void(const boost::system::error_code& ec, std::size_t)> on_read;
  std::function<void(const boost::system::error_code& ec, std::size_t)> on_write;
  bool closed;
};


class IncludeOSTCPService:public boost::asio::io_service::service
{
public:
  static boost::asio::io_service::id id;
  typedef IncludeOSTCPHandle implementation_type;
  typedef void* native_handle_type;
  typedef boost::asio::ip::tcp::endpoint endpoint;
  typedef boost::system::error_code error_code;
  typedef boost::asio::socket_base socket_base;
  typedef boost::asio::const_buffer const_buffer;
  typedef std::function<void(const error_code& ec, std::size_t)> RH;
  typedef std::function<void(const error_code& ec)> CH;
  IncludeOSTCPService(boost::asio::io_service& io);
  void construct(IncludeOSTCPHandle handle);
  void destroy(IncludeOSTCPHandle handle);
  void shutdown_service() override;
  void move_construct(IncludeOSTCPHandle& to, IncludeOSTCPHandle& from);
  template<typename...T>
  error_code set_option(T... args)
  {
    return error_code();
  }
  template<typename P>
  error_code open(IncludeOSTCPHandle& s, P p, error_code& ec)
  {
    ec = error_code();
    return ec;
  }
  template<typename P>
  error_code assign(IncludeOSTCPHandle& s, P p, void* n, error_code& ec)
  {
    s.assign(net::tcp::Connection_ptr((net::tcp::Connection*)n));
    ec = error_code();
    return ec;
  }
  bool is_open(IncludeOSTCPHandle const& h) const;
  error_code close(IncludeOSTCPHandle& h, error_code& ec);
  int native_handle(IncludeOSTCPHandle& h);
  error_code cancel(IncludeOSTCPHandle& h, error_code& ec);
  size_t available(IncludeOSTCPHandle& h);
  error_code bind(IncludeOSTCPHandle& h, boost::asio::ip::tcp::endpoint ep, error_code& ec);
  error_code shutdown(IncludeOSTCPHandle& h, boost::asio::socket_base::shutdown_type, error_code& ec);
  endpoint local_endpoint(IncludeOSTCPHandle const& h, error_code& ec) const;
  endpoint remote_endpoint(IncludeOSTCPHandle const& h, error_code& ec) const;
  error_code connect(IncludeOSTCPHandle& h, endpoint, error_code& ec);
  void async_connect(IncludeOSTCPHandle& h, endpoint, CH cb);
  void async_receive(IncludeOSTCPHandle& b, boost::asio::mutable_buffer mb,
    socket_base::message_flags f, RH cb);
  void async_send(IncludeOSTCPHandle& b, boost::asio::const_buffer cb,
                     socket_base::message_flags f, RH wh);
  net::Inet4& stack;
};

typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, IncludeOSTCPService>
IncludeOSTCPSocket;

class IncludeOSTCPAcceptorHandle
{
public:
  IncludeOSTCPAcceptorHandle()
  : listener(nullptr)
  , target(nullptr)
  {}
  net::tcp::Listener* listener;
  boost::asio::ip::tcp::endpoint endpoint;
  
  boost::asio::basic_socket<boost::asio::ip::tcp, IncludeOSTCPService>* target;
  boost::asio::ip::tcp::endpoint* target_endpoint;
  std::function<void(const boost::system::error_code&)> cb;
  std::vector<net::tcp::Connection_ptr> inbounds;
};

class IncludeOSTCPAcceptorService:public boost::asio::io_service::service
{
public:
  static boost::asio::io_service::id id;
  typedef IncludeOSTCPAcceptorHandle implementation_type;
  typedef int native_handle_type;
  typedef boost::asio::ip::tcp::endpoint endpoint;
  typedef boost::system::error_code error_code;
  typedef std::function<void(const error_code&)> AH;

  IncludeOSTCPAcceptorService(boost::asio::io_service& io);
  void construct(IncludeOSTCPAcceptorHandle handle);
  void destroy(IncludeOSTCPAcceptorHandle handle);
  void shutdown_service() override;
  void move_construct(IncludeOSTCPAcceptorHandle& to, IncludeOSTCPAcceptorHandle& from);
  template<typename P>
  error_code open(IncludeOSTCPAcceptorHandle& s, P p, error_code& ec)
  {
    ec = error_code();
    return ec;
  }
  template<typename...T>
  error_code set_option(T... args)
  {
    return error_code();
  }
  bool is_open(IncludeOSTCPAcceptorHandle const& h) const;
  error_code close(IncludeOSTCPAcceptorHandle& h, error_code& ec);
  int native_handle(IncludeOSTCPAcceptorHandle& h);
  error_code cancel(IncludeOSTCPAcceptorHandle& h, error_code& ec);
  endpoint local_endpoint(IncludeOSTCPAcceptorHandle const& h, error_code& ec) const;
  error_code bind(IncludeOSTCPAcceptorHandle& h, endpoint ep, error_code& ec);
  error_code listen(IncludeOSTCPAcceptorHandle& h, size_t, error_code& ec);
  void async_accept(IncludeOSTCPAcceptorHandle& h,
                    boost::asio::basic_socket<boost::asio::ip::tcp, IncludeOSTCPService>& tgt,
                    endpoint* ep,
                    AH ah);
  net::Inet4& stack;
};

typedef boost::asio::basic_socket_acceptor<boost::asio::ip::tcp, IncludeOSTCPAcceptorService>
IncludeOSTCPAcceptor;

typedef std::function<void(const boost::system::error_code&)> WaitHandler;
class IncludeOSTimerImpl
{
public:
  IncludeOSTimerImpl();
  boost::posix_time::ptime expiration;
  std::vector<WaitHandler> listeners;
  int timer_id;
};

class IncludeOSTimerService: public boost::asio::io_service::service
{
public:
  static boost::asio::io_service::id id;
  typedef IncludeOSTimerImpl implementation_type;
  typedef boost::system::error_code error_code;
  typedef boost::posix_time::ptime Time;
  typedef boost::asio::time_traits<Time> TimeTraits;
  typedef TimeTraits::duration_type Duration;
  IncludeOSTimerService(boost::asio::io_service& io);
  void shutdown_service();
  void construct(IncludeOSTimerImpl& mt);
  void destroy(IncludeOSTimerImpl& mt);
  size_t cancel(IncludeOSTimerImpl& mt, error_code& erc);
  Time expires_at(IncludeOSTimerImpl const& mt);
  size_t expires_at(IncludeOSTimerImpl& mt, Time when, error_code& erc);
  Duration expires_from_now(IncludeOSTimerImpl const& mt);
  size_t expires_from_now(IncludeOSTimerImpl& mt,
                          TimeTraits::duration_type d,
                          error_code& erc);
  error_code wait(IncludeOSTimerImpl const& mt, error_code& erc);
  void async_wait(IncludeOSTimerImpl& mt, WaitHandler cb);
};

typedef boost::asio::basic_deadline_timer<
  boost::posix_time::ptime,
  boost::asio::time_traits<boost::posix_time::ptime>,
  IncludeOSTimerService> IncludeOSTimer;

#endif