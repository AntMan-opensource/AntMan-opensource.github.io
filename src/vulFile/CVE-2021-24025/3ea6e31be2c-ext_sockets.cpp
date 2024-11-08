



































namespace HPHP {



static void check_socket_parameters(int &domain, int &type) {
  if (domain != AF_UNIX && domain != AF_INET6 && domain != AF_INET) {
    raise_warning("invalid socket domain [%d] specified for argument 1, " "assuming AF_INET", domain);
    domain = AF_INET;
  }

  if (type > 10) {
    raise_warning("invalid socket type [%d] specified for argument 2, " "assuming SOCK_STREAM", type);
    type = SOCK_STREAM;
  }
}

const StaticString s_2colons("::"), s_0_0_0_0("0.0.0.0");


static bool get_sockaddr(sockaddr *sa, socklen_t salen, Variant &address, Variant &port) {
  switch (sa->sa_family) {
  case AF_INET6:
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
      try {
        folly::SocketAddress addr;
        addr.setFromSockaddr(sin6);

        address = String(addr.getAddressStr(), CopyString);
        port = addr.getPort();
      } catch (...) {
        address = s_2colons;
        port = 0;
      }
    }
    return true;
  case AF_INET:
    {
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      try {
        folly::SocketAddress addr;
        addr.setFromSockaddr(sin);

        address = String(addr.getAddressStr(), CopyString);
        port = addr.getPort();
      } catch (...) {
        address = s_0_0_0_0;
        port = 0;
      }
    }
    return true;
  case AF_UNIX:
    {

      address = String("Unsupported");

      
      
      
      struct sockaddr_un *s_un = (struct sockaddr_un *)sa;
      if (salen > offsetof(sockaddr_un, sun_path)) {
        
        
        const auto max_path_len = salen - offsetof(struct sockaddr_un, sun_path);
        const auto actual_path_len = ::strnlen(s_un->sun_path, max_path_len);
        address = String(s_un->sun_path, actual_path_len, CopyString);
      } else {
        address = empty_string();
      }

    }
    return true;

  default:
    break;
  }

  raise_warning("Unsupported address family %d", sa->sa_family);
  return false;
}

namespace {
static bool php_string_to_if_index(const char *val, unsigned *out)
{

  unsigned int ind = if_nametoindex(val);
  if (ind == 0) {
    raise_warning("no interface with name \"%s\" could be found", val);
    return false;
  } else {
    *out = ind;
    return true;
  }

  raise_warning("this platform does not support looking up an interface by " "name, an integer interface index must be supplied instead");
  return false;

}
} 

static bool php_set_inet6_addr(struct sockaddr_in6 *sin6, const char *address, req::ptr<Socket> sock) {

  struct in6_addr tmp;
  struct addrinfo hints;
  struct addrinfo *addrinfo = NULL;

  if (inet_pton(AF_INET6, address, &tmp)) {
    memcpy(&(sin6->sin6_addr.s6_addr), &(tmp.s6_addr), sizeof(struct in6_addr));
  } else {
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_INET6;
    getaddrinfo(address, NULL, &hints, &addrinfo);
    if (!addrinfo) {
      
      SOCKET_ERROR(sock, "Host lookup failed", (-10000 - h_errno));
      return false;
    }
    if (addrinfo->ai_family != PF_INET6 || addrinfo->ai_addrlen != sizeof(struct sockaddr_in6)) {
      raise_warning("Host lookup failed: Non AF_INET6 domain " "returned on AF_INET6 socket");
      freeaddrinfo(addrinfo);
      return false;
    }

    memcpy(&(sin6->sin6_addr.s6_addr), ((struct sockaddr_in6*)(addrinfo->ai_addr))->sin6_addr.s6_addr, sizeof(struct in6_addr));

    freeaddrinfo(addrinfo);
  }

  const char *scope = strchr(address, '%');
  if (scope++) {
    int64_t lval = 0;
    double dval = 0;
    unsigned scope_id = 0;
    if (KindOfInt64 == is_numeric_string(scope, strlen(scope), &lval, &dval, 0)) {
      if (lval > 0 && lval <= UINT_MAX) {
        scope_id = lval;
      }
    } else {
      php_string_to_if_index(scope, &scope_id);
    }

    sin6->sin6_scope_id = scope_id;
  }

  return true;
}

static bool php_set_inet_addr(struct sockaddr_in *sin, const char *address, req::ptr<Socket> sock) {

  struct in_addr tmp;

  if (inet_aton(address, &tmp)) {
    sin->sin_addr.s_addr = tmp.s_addr;
  } else {
    HostEnt result;
    if (!safe_gethostbyname(address, result)) {
      
      SOCKET_ERROR(sock, "Host lookup failed", (-10000 - result.herr));
      return false;
    }
    if (result.hostbuf.h_addrtype != AF_INET) {
      raise_warning("Host lookup failed: Non AF_INET domain " "returned on AF_INET socket");
      return false;
    }
    memcpy(&(sin->sin_addr.s_addr), result.hostbuf.h_addr_list[0], result.hostbuf.h_length);
  }

  return true;
}

static bool set_sockaddr(sockaddr_storage &sa_storage, req::ptr<Socket> sock, const String& addr, int port, struct sockaddr *&sa_ptr, size_t &sa_size) {

  
  
  
  
  
  
  
  memset(&sa_storage, 0, sizeof(struct sockaddr_storage));
  struct sockaddr *sock_type = (struct sockaddr*) &sa_storage;
  switch (sock->getType()) {
  case AF_UNIX:
    {

      return false;

      struct sockaddr_un *sa = (struct sockaddr_un *)sock_type;
      sa->sun_family = AF_UNIX;
      if (addr.length() > sizeof(sa->sun_path)) {
        raise_warning( "Unix socket path length (%d) is larger than system limit (%lu)", addr.length(), sizeof(sa->sun_path)


        );
        return false;
      }
      memcpy(sa->sun_path, addr.data(), addr.length());
      sa_ptr = (struct sockaddr *)sa;
      sa_size = offsetof(struct sockaddr_un, sun_path) + addr.length();

      if (addr.length() == 0) {
        
        
        
        
        
        
        
        
        
        
        
        
        sa_size = offsetof(struct sockaddr_un, sun_path);
      }



    }
    break;
  case AF_INET:
    {
      struct sockaddr_in *sa = (struct sockaddr_in *)sock_type;
      sa->sin_family = AF_INET;
      sa->sin_port = htons((unsigned short) port);
      if (!php_set_inet_addr(sa, addr.c_str(), sock)) {
        return false;
      }
      sa_ptr = (struct sockaddr *)sa;
      sa_size = sizeof(struct sockaddr_in);
    }
    break;
  case AF_INET6:
    {
      struct sockaddr_in6 *sa = (struct sockaddr_in6 *)sock_type;
      sa->sin6_family = AF_INET6;
      sa->sin6_port = htons((unsigned short) port);
      if (!php_set_inet6_addr(sa, addr.c_str(), sock)) {
        return false;
      }
      sa_ptr = (struct sockaddr *)sa;
      sa_size = sizeof(struct sockaddr_in6);
    }
    break;
  default:
    raise_warning("unsupported socket type '%d', must be " "AF_UNIX, AF_INET, or AF_INET6", sock->getType());
    return false;
  }

  
  
  
  
  
  
  
  
  
  
  sa_ptr->sa_len = sa_size;

  return true;
}

static void sock_array_to_fd_set(const Array& sockets, std::vector<pollfd>& fds, const short flag) {
  IterateVNoInc( sockets.get(), [&](TypedValue v) {

      assertx(v.m_type == KindOfResource);
      auto const intfd = static_cast<File*>(v.m_data.pres->data())->fd();
      if (intfd < 0) {
        raise_warning( "cannot represent a stream of type user-space as a file descriptor" );

        return;
      }
      fds.emplace_back();
      auto& fd = fds.back();
      fd.fd = intfd;
      fd.events = flag;
      fd.revents = 0;
    }
  );
}

static void sock_array_from_fd_set(Variant &sockets, const std::vector<pollfd>& fds, int &nfds, int &count, const short flag) {

  Array ret = Array::CreateDArray();
  assertx(sockets.isArray());
  const auto& sock_array = sockets.asCArrRef();
  IterateKVNoInc( sock_array.get(), [&](TypedValue k, TypedValue v) {

      const pollfd &fd = fds.at(nfds++);
      assertx(v.m_type == KindOfResource);
      assertx(fd.fd == static_cast<File*>(v.m_data.pres->data())->fd());
      if (fd.revents & flag) {
        ret.set(k, v);
        count++;
      }
    }
  );
  sockets = ret;
}

static int php_read(req::ptr<Socket> sock, void *buf, int64_t maxlen, int flags) {
  int m = fcntl(sock->fd(), F_GETFL);
  if (m < 0) {
    return m;
  }
  int nonblock = (m & O_NONBLOCK);
  m = 0;

  char *t = (char *)buf;
  *t = '\0';
  int n = 0;
  int no_read = 0;
  while (*t != '\n' && *t != '\r' && n < maxlen) {
    if (m > 0) {
      t++;
      n++;
    } else if (m == 0) {
      no_read++;
      if (nonblock && no_read >= 2) {
        return n;
        
      }

      if (no_read > 200) {
        errno = ECONNRESET;
        return -1;
      }
    }

    if (n < maxlen) {
      m = recv(sock->fd(), (void *)t, 1, flags);
    }

    if (errno != 0 && errno != ESPIPE && errno != EAGAIN) {
      return -1;
    }
    errno = 0;
  }

  if (n < maxlen) {
    n++;
    
  }

  return n;
}

static req::ptr<Socket> create_new_socket( const HostURL &hosturl, Variant& errnum, Variant& errstr, const Variant& context ) {




  int domain = hosturl.isIPv6() ? AF_INET6 : AF_INET;
  int type = SOCK_STREAM;
  const std::string scheme = hosturl.getScheme();

  if (scheme == "udp" || scheme == "udg") {
    type = SOCK_DGRAM;
  }

  if (scheme == "unix" || scheme == "udg") {
    domain = AF_UNIX;
  }

  req::ptr<Socket> sock;
  int fd = socket(domain, type, 0);
  double timeout = RequestInfo::s_requestInfo.getNoCheck()-> m_reqInjectionData.getSocketDefaultTimeout();
  req::ptr<StreamContext> streamctx;
  if (context.isResource()) {
    streamctx = cast<StreamContext>(context.toResource());
  }

  auto sslsock = SSLSocket::Create(fd, domain, hosturl, timeout, streamctx);
  if (sslsock) {
    sock = sslsock;
  } else {
    sock = req::make<StreamSocket>(fd, domain, hosturl.getHost().c_str(), hosturl.getPort());
  }

  if (!sock->valid()) {
    SOCKET_ERROR(sock, "unable to create socket", errno);
    errnum = sock->getError();
    errstr = HHVM_FN(socket_strerror)(sock->getError());
    sock.reset();
  }
  return sock;
}

static int connect_with_timeout(int fd, struct sockaddr *sa_ptr, size_t sa_size, double timeout, const HostURL &hosturl, std::string &errstr, int &errnum) {


  if (timeout <= 0) {
    int retval = connect(fd, sa_ptr, sa_size);
    if (retval < 0) {
      errstr = "unable to connect to " + hosturl.getHostURL();
      errnum = errno;
    }
    return retval;
  }

  
  long arg = fcntl(fd, F_GETFL, nullptr);
  fcntl(fd, F_SETFL, arg | O_NONBLOCK);

  int retval = connect(fd, sa_ptr, sa_size);
  if (retval < 0) {
    if (errno == EINPROGRESS) {
      struct pollfd fds[1];
      fds[0].fd = fd;
      fds[0].events = POLLOUT;
      if (poll(fds, 1, (int)(timeout * 1000))) {
        int valopt;
        socklen_t lon = sizeof(int);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
        if (valopt) {
          errstr = "failed to connect to " + hosturl.getHostURL();
          errnum = valopt;
        }
        retval = valopt ? -1 : 0;
      } else {
        errstr = "timed out after ";
        errstr += folly::to<std::string>(timeout);
        errstr += " seconds when connecting to " + hosturl.getHostURL();
        errnum = ETIMEDOUT;
        retval = -1;
      }
    } else {
      errstr = "unable to connect to " + hosturl.getHostURL();
      errnum = errno;
    }
  }

  
  arg = fcntl(fd, F_GETFL, nullptr);
  fcntl(fd, F_SETFL, arg & ~O_NONBLOCK);

  return retval;
}

static Variant new_socket_connect(const HostURL &hosturl, double timeout, const req::ptr<StreamContext>& streamctx, Variant& errnum, Variant& errstr) {

  int domain = AF_UNSPEC;
  int type = SOCK_STREAM;
  auto const& scheme = hosturl.getScheme();
  req::ptr<Socket> sock;
  req::ptr<SSLSocket> sslsock;
  std::string sockerr;
  int error;

  if (scheme == "udp" || scheme == "udg") {
    type = SOCK_DGRAM;
  }

  if (scheme == "unix" || scheme == "udg") {
    domain = AF_UNIX;
  }

  int fd = -1;
  if (domain == AF_UNIX) {
    sockaddr_storage sa_storage;
    struct sockaddr *sa_ptr;
    size_t sa_size;

    fd = socket(domain, type, 0);
    sock = req::make<StreamSocket>( fd, domain, hosturl.getHost().c_str(), hosturl.getPort(), 0, empty_string_ref, false);


    if (!set_sockaddr(sa_storage, sock, hosturl.getHost(), hosturl.getPort(), sa_ptr, sa_size)) {
      
      return false;
    }
    if (connect_with_timeout(fd, sa_ptr, sa_size, timeout, hosturl, sockerr, error) != 0) {
      SOCKET_ERROR(sock, sockerr.c_str(), error);
      errnum = sock->getLastError();
      errstr = HHVM_FN(socket_strerror)(sock->getLastError());
      return false;
    }
  } else {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = domain;
    hints.ai_socktype = type;

    auto port = folly::to<std::string>(hosturl.getPort());
    auto host = hosturl.getHost();

    struct addrinfo *aiHead;
    int errcode = getaddrinfo(host.c_str(), port.c_str(), &hints, &aiHead);
    if (errcode != 0) {
      errstr = String(gai_strerror(errcode), CopyString);
      return false;
    }
    SCOPE_EXIT { freeaddrinfo(aiHead); };

    for (struct addrinfo *ai = aiHead; ai != nullptr; ai = ai->ai_next) {
      domain = ai->ai_family;
      fd = socket(domain, ai->ai_socktype, ai->ai_protocol);
      if (fd == -1) {
        continue;
      }

      if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, timeout, hosturl, sockerr, error) == 0) {
        break;
      }
      close(fd);
      fd = -1;
    }

    sslsock = SSLSocket::Create(fd, domain, hosturl, timeout, streamctx, false);
    if (sslsock) {
      sock = sslsock;
    } else {
      sock = req::make<StreamSocket>(fd, domain, hosturl.getHost().c_str(), hosturl.getPort(), 0, empty_string_ref, false);





    }
  }

  if (!sock->valid()) {
    SOCKET_ERROR(sock, sockerr.empty() ? "unable to create socket" : sockerr.c_str(), error);
    errnum = sock->getLastError();
    errstr = HHVM_FN(socket_strerror)(sock->getLastError());
    return false;
  }

  if (sslsock && !sslsock->onConnect()) {
    raise_warning("Failed to enable crypto");
    return false;
  }

  return Variant(std::move(sock));
}



Variant HHVM_FUNCTION(socket_create, int domain, int type, int protocol) {


  check_socket_parameters(domain, type);
  int socketId = socket(domain, type, protocol);
  if (socketId == -1) {
    SOCKET_ERROR(req::make<ConcreteSocket>(), "Unable to create socket", errno);

    return false;
  }
  return Variant(req::make<ConcreteSocket>(socketId, domain));
}

Variant HHVM_FUNCTION(socket_create_listen, int port, int backlog ) {

  HostEnt result;
  if (!safe_gethostbyname("0.0.0.0", result)) {
    return false;
  }

  struct sockaddr_in la;
  memcpy((char *) &la.sin_addr, result.hostbuf.h_addr, result.hostbuf.h_length);
  la.sin_family = result.hostbuf.h_addrtype;
  la.sin_port = htons((unsigned short)port);

  auto sock = req::make<ConcreteSocket>( socket(PF_INET, SOCK_STREAM, 0), PF_INET, "0.0.0.0", port);

  if (!sock->valid()) {
    SOCKET_ERROR(sock, "unable to create listening socket", errno);
    return false;
  }

  if (::bind(sock->fd(), (struct sockaddr *)&la, sizeof(la)) < 0) {
    SOCKET_ERROR(sock, "unable to bind to given address", errno);
    return false;
  }

  if (listen(sock->fd(), backlog) < 0) {
    SOCKET_ERROR(sock, "unable to listen on socket", errno);
    return false;
  }

  return Variant(std::move(sock));
}

const StaticString s_socktype_generic("generic_socket");

bool socket_create_pair_impl(int domain, int type, int protocol, Variant& fd, bool asStream) {
  check_socket_parameters(domain, type);

  int fds_array[2];
  if (socketpair(domain, type, protocol, fds_array) != 0) {
    SOCKET_ERROR(req::make<StreamSocket>(), "unable to create socket pair", errno);

    return false;
  }

  if (asStream) {
    fd = make_varray( Variant(req::make<StreamSocket>(fds_array[0], domain, nullptr, 0, 0.0, s_socktype_generic)), Variant(req::make<StreamSocket>(fds_array[1], domain, nullptr, 0, 0.0, s_socktype_generic))



    );
  } else {
    fd = make_varray( Variant(req::make<ConcreteSocket>(fds_array[0], domain, nullptr, 0, 0.0, s_socktype_generic)), Variant(req::make<ConcreteSocket>(fds_array[1], domain, nullptr, 0, 0.0, s_socktype_generic))



    );
  }
  return true;
}

bool HHVM_FUNCTION(socket_create_pair, int domain, int type, int protocol, Variant& fd) {



  return socket_create_pair_impl(domain, type, protocol, fd, false);
}

const StaticString s_l_onoff("l_onoff"), s_l_linger("l_linger"), s_sec("sec"), s_usec("usec");




Variant HHVM_FUNCTION(socket_get_option, const Resource& socket, int level, int optname) {


  auto sock = cast<Socket>(socket);
  socklen_t optlen;

  switch (optname) {
  case SO_LINGER:
    {
      struct linger linger_val;
      optlen = sizeof(linger_val);
      if (getsockopt(sock->fd(), level, optname, (char*)&linger_val, &optlen) != 0) {
        SOCKET_ERROR(sock, "unable to retrieve socket option", errno);
        return false;
      }

      return make_darray( s_l_onoff, linger_val.l_onoff, s_l_linger, linger_val.l_linger );


    }
    break;

  case SO_RCVTIMEO:
  case SO_SNDTIMEO:
    {
      struct timeval tv;
      optlen = sizeof(tv);
      if (getsockopt(sock->fd(), level, optname, (char*)&tv, &optlen) != 0) {
        SOCKET_ERROR(sock, "unable to retrieve socket option", errno);
        return false;
      }
      return make_darray( s_sec,  (int)tv.tv_sec, s_usec, (int)tv.tv_usec );


    }
    break;

  default:
    {
      int other_val;
      optlen = sizeof(other_val);
      if (getsockopt(sock->fd(), level, optname, (char*)&other_val, &optlen)) {
        SOCKET_ERROR(sock, "unable to retrieve socket option", errno);
        return false;
      }
      return other_val;
    }
  }
  not_reached();
}

bool HHVM_FUNCTION(socket_getpeername, const Resource& socket, Variant& address, Variant& port) {


  auto sock = cast<Socket>(socket);

  sockaddr_storage sa_storage;
  socklen_t salen = sizeof(sockaddr_storage);
  struct sockaddr *sa = (struct sockaddr *)&sa_storage;
  if (getpeername(sock->fd(), sa, &salen) < 0) {
    SOCKET_ERROR(sock, "unable to retrieve peer name", errno);
    return false;
  }
  Variant a, p;
  auto ret = get_sockaddr(sa, salen, a, p);
  address = a;
  port = p;
  return ret;
}

bool HHVM_FUNCTION(socket_getsockname, const Resource& socket, Variant& address, Variant& port) {


  auto sock = cast<Socket>(socket);

  sockaddr_storage sa_storage;
  socklen_t salen = sizeof(sockaddr_storage);
  struct sockaddr *sa = (struct sockaddr *)&sa_storage;
  if (getsockname(sock->fd(), sa, &salen) < 0) {
    SOCKET_ERROR(sock, "unable to retrieve peer name", errno);
    return false;
  }
  Variant a, p;
  auto ret = get_sockaddr(sa, salen, a, p);
  address = a;
  port = p;
  return ret;
}

bool HHVM_FUNCTION(socket_set_block, const Resource& socket) {
  return cast<Socket>(socket)->setBlocking(true);
}

bool HHVM_FUNCTION(socket_set_nonblock, const Resource& socket) {
  return cast<Socket>(socket)->setBlocking(false);
}

bool HHVM_FUNCTION(socket_set_option, const Resource& socket, int level, int optname, const Variant& optval) {



  auto sock = cast<Socket>(socket);

  struct linger lv;
  struct timeval tv;
  int ov;
  int optlen;
  void *opt_ptr;

  switch (optname) {
  case SO_LINGER:
    {
      Array value = optval.toArray();
      if (!value.exists(s_l_onoff)) {
        raise_warning("no key \"l_onoff\" passed in optval");
        return false;
      }
      if (!value.exists(s_l_linger)) {
        raise_warning("no key \"l_linger\" passed in optval");
        return false;
      }

      lv.l_onoff = (unsigned short)value[s_l_onoff].toInt32();
      lv.l_linger = (unsigned short)value[s_l_linger].toInt32();
      optlen = sizeof(lv);
      opt_ptr = &lv;
    }
    break;

  case SO_RCVTIMEO:
  case SO_SNDTIMEO:
    {
      Array value = optval.toArray();
      if (!value.exists(s_sec)) {
        raise_warning("no key \"sec\" passed in optval");
        return false;
      }
      if (!value.exists(s_usec)) {
        raise_warning("no key \"usec\" passed in optval");
        return false;
      }

      tv.tv_sec = value[s_sec].toInt32();
      tv.tv_usec = value[s_usec].toInt32();
      if (tv.tv_usec >= 1000000) {
        tv.tv_sec += tv.tv_usec / 1000000;
        tv.tv_usec %= 1000000;
      }
      if (tv.tv_sec < 0) {
        tv.tv_sec = RequestInfo::s_requestInfo.getNoCheck()-> m_reqInjectionData.getSocketDefaultTimeout();
      }
      optlen = sizeof(tv);
      opt_ptr = &tv;
      sock->internalSetTimeout(tv);
    }
    break;

  default:
    ov = optval.toInt32();
    optlen = sizeof(ov);
    opt_ptr = &ov;
    break;
  }

  if (setsockopt(sock->fd(), level, optname, opt_ptr, optlen) != 0) {
    SOCKET_ERROR(sock, "unable to set socket option", errno);
    return false;
  }
  return true;
}

bool HHVM_FUNCTION(socket_connect, const Resource& socket, const String& address, int port ) {


  auto sock = cast<Socket>(socket);

  switch (sock->getType()) {
  case AF_INET6:
  case AF_INET:
    if (port == 0) {
      raise_warning("Socket of type AF_INET/6 requires 3 arguments");
      return false;
    }
    break;
  default:
    break;
  }

  sockaddr_storage sa_storage;
  struct sockaddr *sa_ptr;
  size_t sa_size;
  if (!set_sockaddr(sa_storage, sock, address, port, sa_ptr, sa_size)) {
    return false;
  }

  IOStatusHelper io("socket::connect", address.data(), port);
  int retval = connect(sock->fd(), sa_ptr, sa_size);
  if (retval != 0) {
    std::string msg = "unable to connect to ";
    msg += address.data();
    msg += ":";
    msg += folly::to<std::string>(port);
    SOCKET_ERROR(sock, msg.c_str(), errno);
    return false;
  }

  return true;
}

bool HHVM_FUNCTION(socket_bind, const Resource& socket, const String& address, int port ) {


  auto sock = cast<Socket>(socket);

  sockaddr_storage sa_storage;
  struct sockaddr *sa_ptr;
  size_t sa_size;
  if (!set_sockaddr(sa_storage, sock, address, port, sa_ptr, sa_size)) {
    return false;
  }

  long retval = ::bind(sock->fd(), sa_ptr, sa_size);
  if (retval != 0) {
    std::string msg = "unable to bind address";
    msg += address.data();
    msg += ":";
    msg += folly::to<std::string>(port);
    SOCKET_ERROR(sock, msg.c_str(), errno);
    return false;
  }

  return true;
}

bool HHVM_FUNCTION(socket_listen, const Resource& socket, int backlog ) {

  auto sock = cast<Socket>(socket);
  if (listen(sock->fd(), backlog) != 0) {
    SOCKET_ERROR(sock, "unable to listen on socket", errno);
    return false;
  }
  return true;
}

Variant HHVM_FUNCTION(socket_select, Variant& read, Variant& write, Variant& except, const Variant& vtv_sec, int tv_usec ) {




  int count = 0;
  if (!read.isNull()) {
    if (!read.isArray()) {
      raise_warning("socket_select() expects parameter 1 to be array()");
      return init_null();
    }
    count += read.asCArrRef().size();
  }
  if (!write.isNull()) {
    if (!write.isArray()) {
      raise_warning("socket_select() expects parameter 2 to be array()");
      return init_null();
    }
    count += write.asCArrRef().size();
  }
  if (!except.isNull()) {
    if (!except.isArray()) {
      raise_warning("socket_select() expects parameter 3 to be array()");
      return init_null();
    }
    count += except.asCArrRef().size();
  }
  if (!count) {
    return false;
  }

  std::vector<pollfd> fds;
  fds.reserve(count);
  if (!read.isNull()) {
    sock_array_to_fd_set(read.asCArrRef(), fds, POLLIN);
  }
  if (!write.isNull()) {
    sock_array_to_fd_set(write.asCArrRef(), fds, POLLOUT);
  }
  if (!except.isNull()) {
    sock_array_to_fd_set(except.asCArrRef(), fds, POLLPRI);
  }
  if (fds.empty()) {
    raise_warning("no resource arrays were passed to select");
    return false;
  }

  IOStatusHelper io("socket_select");
  int timeout_ms = -1;
  if (!vtv_sec.isNull()) {
    timeout_ms = vtv_sec.toInt32() * 1000 + tv_usec / 1000;
  }

  
  if (!read.isNull()) {
    
    
    auto hasData = Array::CreateDArray();
    IterateVNoInc( read.asCArrRef().get(), [&](TypedValue v) {

        assertx(v.m_type == KindOfResource);
        auto file = static_cast<File*>(v.m_data.pres->data());
        if (file->bufferedLen() > 0) {
          hasData.append(v);
        }
      }
    );
    if (hasData.size() > 0) {
      write = empty_darray();
      except = empty_darray();
      read = hasData;
      return hasData.size();
    }
  }

  int retval = poll(fds.data(), fds.size(), timeout_ms);
  if (retval == -1) {
    raise_warning("unable to select [%d]: %s", errno, folly::errnoStr(errno).c_str());
    return false;
  }

  count = 0;
  int nfds = 0;
  if (!read.isNull()) {
    sock_array_from_fd_set(read, fds, nfds, count, POLLIN|POLLERR|POLLHUP);
  }
  if (!write.isNull()) {
    sock_array_from_fd_set(write, fds, nfds, count, POLLOUT|POLLERR);
  }
  if (!except.isNull()) {
    sock_array_from_fd_set(except, fds, nfds, count, POLLPRI|POLLERR);
  }

  return count;
}

Variant HHVM_FUNCTION(socket_server, const String& hostname, int port, Variant& errnum, Variant& errstr) {



  HostURL hosturl(static_cast<const std::string>(hostname), port);
  return socket_server_impl(hosturl, k_STREAM_SERVER_BIND|k_STREAM_SERVER_LISTEN, errnum, errstr);

}

Variant socket_server_impl( const HostURL &hosturl, int flags, Variant& errnum, Variant& errstr, const Variant& context ) {





  errnum = 0;
  errstr = empty_string();
  auto sock = create_new_socket(hosturl, errnum, errstr, context);
  if (!sock) {
    return false;
  }

  sockaddr_storage sa_storage;
  struct sockaddr *sa_ptr;
  size_t sa_size;
  if (!set_sockaddr(sa_storage, sock, hosturl.getHost(), hosturl.getPort(), sa_ptr, sa_size)) {
    return false;
  }
  int yes = 1;
  setsockopt(sock->fd(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if ((flags & k_STREAM_SERVER_BIND) != 0 && ::bind(sock->fd(), sa_ptr, sa_size) < 0) {
    SOCKET_ERROR(sock, "unable to bind to given address", errno);
    return false;
  }
  if ((flags & k_STREAM_SERVER_LISTEN) != 0 && listen(sock->fd(), 128) < 0) {
    SOCKET_ERROR(sock, "unable to listen on socket", errno);
    return false;
  }

  return Variant(std::move(sock));
}

Variant HHVM_FUNCTION(socket_accept, const Resource& socket) {
  auto sock = cast<Socket>(socket);
  struct sockaddr sa;
  socklen_t salen = sizeof(sa);
  auto new_sock = req::make<ConcreteSocket>( accept(sock->fd(), &sa, &salen), sock->getType());
  if (!new_sock->valid()) {
    SOCKET_ERROR(new_sock, "unable to accept incoming connection", errno);
    return false;
  }
  return Variant(std::move(new_sock));
}

Variant HHVM_FUNCTION(socket_read, const Resource& socket, int64_t length, int type ) {


  if (length <= 0) {
    return false;
  }
  auto sock = cast<Socket>(socket);

  char *tmpbuf = (char *)malloc(length + 1);
  int retval;
  if (type == PHP_NORMAL_READ) {
    retval = php_read(sock, tmpbuf, length, 0);
  } else {
    retval = recv(sock->fd(), tmpbuf, (size_t)length, 0);
  }

  if (retval == -1) {
    
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      sock->setError(errno);
    } else {
      SOCKET_ERROR(sock, "unable to read from socket", errno);
    }

    free(tmpbuf);
    return false;
  }

  tmpbuf[retval] = '\0' ;
  return String(tmpbuf, retval, AttachString);
}

Variant HHVM_FUNCTION(socket_write, const Resource& socket, const String& buffer, int64_t length ) {


  auto sock = cast<Socket>(socket);
  if (length < 0) return false;
  if (length == 0 || length > buffer.size()) {
    length = buffer.size();
  }
  int retval = write(sock->fd(), buffer.data(), (size_t)length);
  if (retval < 0) {
    SOCKET_ERROR(sock, "unable to write to socket", errno);
    return false;
  }
  return retval;
}

Variant HHVM_FUNCTION(socket_send, const Resource& socket, const String& buf, int64_t len, int flags) {



  auto sock = cast<Socket>(socket);
  if (len < 0) return false;
  if (len > buf.size()) {
    len = buf.size();
  }
  int retval = send(sock->fd(), buf.data(), (size_t)len, flags);
  if (retval == -1) {
    SOCKET_ERROR(sock, "unable to write to socket", errno);
    return false;
  }
  return retval;
}

Variant HHVM_FUNCTION(socket_sendto, const Resource& socket, const String& buf, int64_t len, int flags, const String& addr, int port ) {





  auto sock = cast<Socket>(socket);
  if (len < 0) return false;
  if (len > buf.size()) {
    len = buf.size();
  }
  int retval;
  switch (sock->getType()) {
  case AF_UNIX:
    {

      retval = -1;

      struct sockaddr_storage s_s;
      struct sockaddr* sa_ptr;
      size_t sa_size;
      if (!set_sockaddr(s_s, sock, addr, 0, sa_ptr, sa_size)) {
        return false;
      }

      retval = sendto(sock->fd(), buf.data(), (size_t)len, flags, sa_ptr, sa_size);

    }
    break;
  case AF_INET:
    {
      if (port == -1) {
        throw_missing_arguments_nr("socket_sendto", 6, 5);
        return false;
      }

      struct sockaddr_in  sin;
      memset(&sin, 0, sizeof(sin));
      sin.sin_family = AF_INET;
      sin.sin_port = htons((unsigned short) port);
      if (!php_set_inet_addr(&sin, addr.c_str(), sock)) {
        return false;
      }

      retval = sendto(sock->fd(), buf.data(), (size_t)len, flags, (struct sockaddr *)&sin, sizeof(sin));
    }
    break;
  case AF_INET6:
    {
      if (port == -1) {
        throw_missing_arguments_nr("socket_sendto", 6, 5);
        return false;
      }

      struct sockaddr_in6  sin6;
      memset(&sin6, 0, sizeof(sin6));
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons((unsigned short) port);

      if (!php_set_inet6_addr(&sin6, addr.c_str(), sock)) {
        return false;
      }

      retval = sendto(sock->fd(), buf.data(), (size_t)len, flags, (struct sockaddr *)&sin6, sizeof(sin6));
    }
    break;
  default:
    raise_warning("Unsupported socket type %d", sock->getType());
    return false;
  }

  if (retval == -1) {
    SOCKET_ERROR(sock, "unable to write to socket", errno);
    return false;
  }

  return retval;
}

Variant HHVM_FUNCTION(socket_recv, const Resource& socket, Variant& buf, int64_t len, int flags) {



  if (len <= 0) {
    return false;
  }
  auto sock = cast<Socket>(socket);

  char *recv_buf = (char *)malloc(len + 1);
  int retval;
  if ((retval = recv(sock->fd(), recv_buf, (size_t)len, flags)) < 1) {
    free(recv_buf);
    buf = init_null();
  } else {
    recv_buf[retval] = '\0';
    buf = String(recv_buf, retval, AttachString);
  }

  if (retval == -1) {
    SOCKET_ERROR(sock, "unable to read from socket", errno);
    return false;
  }
  return retval;
}

Variant HHVM_FUNCTION(socket_recvfrom, const Resource& socket, Variant& buf, int64_t len, int flags, Variant& name, Variant& port) {





  if (len <= 0) {
    return false;
  }

  auto sock = cast<Socket>(socket);

  char *recv_buf = (char *)malloc(len + 2);
  socklen_t slen;
  int retval;

  switch (sock->getType()) {
  case AF_UNIX:
    {

      return false;

      struct sockaddr_un s_un;
      slen = sizeof(s_un);
      memset(&s_un, 0, slen);
      s_un.sun_family = AF_UNIX;
      retval = recvfrom(sock->fd(), recv_buf, (size_t)len, flags, (struct sockaddr *)&s_un, (socklen_t *)&slen);
      if (retval < 0) {
        free(recv_buf);
        SOCKET_ERROR(sock, "unable to recvfrom", errno);
        return false;
      }

      recv_buf[retval] = 0;
      buf = String(recv_buf, retval, AttachString);
      
      
      const auto max_path_len = slen - offsetof(struct sockaddr_un, sun_path);
      const auto actual_path_len = ::strnlen(s_un.sun_path, max_path_len);
      name = String(s_un.sun_path, actual_path_len, CopyString);

    }
    break;
  case AF_INET:
    {
      struct sockaddr_in sin;
      slen = sizeof(sin);
      memset(&sin, 0, slen);
      sin.sin_family = AF_INET; 

      retval = recvfrom(sock->fd(), recv_buf, (size_t)len, flags, (struct sockaddr *)&sin, (socklen_t *)&slen);
      if (retval < 0) {
        free(recv_buf);
        SOCKET_ERROR(sock, "unable to recvfrom", errno);
        return false;
      }
      recv_buf[retval] = 0;
      buf = String(recv_buf, retval, AttachString);

      try {
        folly::SocketAddress addr;
        addr.setFromSockaddr(&sin);

        name = String(addr.getAddressStr(), CopyString);
        port = addr.getPort();
      } catch (...) {
        name = s_0_0_0_0;
        port = 0;
      }
    }
    break;
  case AF_INET6:
    {
      struct sockaddr_in6 sin6;
      slen = sizeof(sin6);
      memset(&sin6, 0, slen);
      sin6.sin6_family = AF_INET6; 

      retval = recvfrom(sock->fd(), recv_buf, (size_t)len, flags, (struct sockaddr *)&sin6, (socklen_t *)&slen);
      if (retval < 0) {
        free(recv_buf);
        SOCKET_ERROR(sock, "unable to recvfrom", errno);
        return false;
      }

      recv_buf[retval] = 0;
      buf = String(recv_buf, retval, AttachString);

      try {
        folly::SocketAddress addr;
        addr.setFromSockaddr(&sin6);

        name = String(addr.getAddressStr(), CopyString);
        port = addr.getPort();
      } catch (...) {
        name = s_2colons;
        port = 0;
      }
    }
    break;
  default:
    raise_warning("Unsupported socket type %d", sock->getType());
    return false;
  }

  return retval;
}

bool HHVM_FUNCTION(socket_shutdown, const Resource& socket, int how ) {

  
  if (socket->instanceof<MemFile>()) {
    return true;
  }
  auto sock = cast<Socket>(socket);
  if (shutdown(sock->fd(), how) != 0) {
    SOCKET_ERROR(sock, "unable to shutdown socket", errno);
    return false;
  }
  return true;
}

void HHVM_FUNCTION(socket_close, const Resource& socket) {
  cast<Socket>(socket)->close();
}

String HHVM_FUNCTION(socket_strerror, int errnum) {
  
  if (errnum < -10000) {
    errnum = (-errnum) - 10000;

    return String(hstrerror(errnum), CopyString);

    return folly::format("Host lookup error {}", errnum).str();
  }

  return String(folly::errnoStr(errnum));
}

int64_t HHVM_FUNCTION(socket_last_error, const Variant& socket ) {
  if (!socket.isNull()) {
    return cast<Socket>(socket)->getError();
  }
  return Socket::getLastError();
}

void HHVM_FUNCTION(socket_clear_error, const Variant& socket ) {
  if (!socket.isNull()) {
    cast<Socket>(socket)->setError(0);
  }
}



namespace {
using SocketMap = std::unordered_map<std::string, std::shared_ptr<SocketData>>;
RDS_LOCAL(SocketMap, s_sockets);
}

Variant sockopen_impl(const HostURL &hosturl, Variant& errnum, Variant& errstr, double timeout, bool persistent, const Variant& context) {

  errnum = 0;
  errstr = empty_string();
  std::string key;
  if (persistent) {
    key = hosturl.getHostURL() + ":" + folly::to<std::string>(hosturl.getPort());

    
    
    auto sockItr = s_sockets->find(key);
    if (sockItr != s_sockets->end()) {
      req::ptr<Socket> sock;
      if (auto sslSocketData = std::dynamic_pointer_cast<SSLSocketData>(sockItr->second)) {
        sock = req::make<SSLSocket>(sslSocketData);
      } else {
        sock = req::make<StreamSocket>(sockItr->second);
      }

      if (sock->getError() == 0 && sock->checkLiveness()) {
        return Variant(sock);
      }

      
      
      sock->close();
      s_sockets->erase(sockItr);
    }
  }

  if (timeout < 0) {
    timeout = RequestInfo::s_requestInfo.getNoCheck()-> m_reqInjectionData.getSocketDefaultTimeout();
  }


  req::ptr<StreamContext> streamctx;
  if (context.isResource()) {
    streamctx = cast<StreamContext>(context.toResource());
  }
  auto socket = new_socket_connect(hosturl, timeout, streamctx, errnum, errstr);
  if (!socket.isResource()) {
    return false;
  }

  if (persistent) {
    assertx(!key.empty());
    (*s_sockets)[key] = cast<Socket>(socket)->getData();
    assertx((*s_sockets)[key]);
  }

  return socket;
}

Variant HHVM_FUNCTION(fsockopen, const String& hostname, int port, Variant& errnum, Variant& errstr, double timeout ) {




  HostURL hosturl(static_cast<const std::string>(hostname), port);
  return sockopen_impl(hosturl, errnum, errstr, timeout, false, uninit_variant);
}

Variant HHVM_FUNCTION(pfsockopen, const String& hostname, int port, Variant& errnum, Variant& errstr, double timeout ) {




  HostURL hosturl(static_cast<const std::string>(hostname), port);
  return sockopen_impl(hosturl, errnum, errstr, timeout, true, uninit_variant);
}

String ipaddr_convert(struct sockaddr *addr, int addrlen) {
  char buffer[NI_MAXHOST];
  int error = getnameinfo(addr, addrlen, buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST);

  if (error) {
    raise_warning("%s", gai_strerror(error));
    return empty_string();
  }
  return String(buffer, CopyString);
}

const StaticString s_family("family"), s_socktype("socktype"), s_protocol("protocol"), s_address("address"), s_port("port"), s_flow_info("flow_info"), s_scope_id("scope_id"), s_sockaddr("sockaddr");








Variant HHVM_FUNCTION(getaddrinfo, const String& host, const String& port, int family , int socktype , int protocol , int flags ) {





  const char *hptr = NULL, *pptr = NULL;
  if (!host.empty()) {
    hptr = host.c_str();
  }
  if (!port.empty()) {
    pptr = port.c_str();
  }

  struct addrinfo hints, *res;
  struct addrinfo *res0 = NULL;
  int error;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  hints.ai_protocol = protocol;
  hints.ai_flags = flags;
  error = getaddrinfo(hptr, pptr, &hints, &res0);

  if (error) {
    raise_warning("%s", gai_strerror(error));

    if (res0) {
      freeaddrinfo(res0);
    }
    return false;
  }

  Array ret = Array::CreateVArray();

  for (res = res0; res; res = res->ai_next) {
    Array data = make_darray( s_family, res->ai_family, s_socktype, res->ai_socktype, s_protocol, res->ai_protocol );




    switch (res->ai_addr->sa_family) {
      case AF_INET:
      {
        struct sockaddr_in *a;
        String buffer = ipaddr_convert(res->ai_addr, sizeof(*a));
        if (!buffer.empty()) {
          a = (struct sockaddr_in *)res->ai_addr;
          data.set( s_sockaddr, make_darray( s_address, buffer, s_port, ntohs(a->sin_port)



            )
          );
        }
        break;
      }
      case AF_INET6:
      {
        struct sockaddr_in6 *a;
        String buffer = ipaddr_convert(res->ai_addr, sizeof(*a));
        if (!buffer.empty()) {
          a = (struct sockaddr_in6 *)res->ai_addr;
          data.set( s_sockaddr, make_darray( s_address, buffer, s_port, ntohs(a->sin6_port), s_flow_info, (int32_t)a->sin6_flowinfo, s_scope_id, (int32_t)a->sin6_scope_id )






          );
        }
        break;
      }
      default:
        data.set(s_sockaddr, empty_array());
        break;
    }

    ret.append(data);
  }

  if (res0) {
    freeaddrinfo(res0);
  }

  return ret;
}

struct SocketsExtension final : Extension {
  SocketsExtension() : Extension("sockets", NO_EXTENSION_VERSION_YET) {}

  void moduleInit() override {
    HHVM_RC_INT_SAME(AF_UNIX);
    HHVM_RC_INT_SAME(AF_INET);
    HHVM_RC_INT_SAME(AF_INET6);
    HHVM_RC_INT_SAME(SOCK_STREAM);
    HHVM_RC_INT_SAME(SOCK_DGRAM);
    HHVM_RC_INT_SAME(SOCK_RAW);
    HHVM_RC_INT_SAME(SOCK_SEQPACKET);
    HHVM_RC_INT_SAME(SOCK_RDM);

    HHVM_RC_INT_SAME(MSG_OOB);
    HHVM_RC_INT_SAME(MSG_WAITALL);
    HHVM_RC_INT_SAME(MSG_CTRUNC);
    HHVM_RC_INT_SAME(MSG_TRUNC);
    HHVM_RC_INT_SAME(MSG_PEEK);
    HHVM_RC_INT_SAME(MSG_DONTROUTE);

    HHVM_RC_INT_SAME(MSG_EOR);


    HHVM_RC_INT_SAME(MSG_EOF);


    HHVM_RC_INT_SAME(MSG_CONFIRM);


    HHVM_RC_INT_SAME(MSG_ERRQUEUE);


    HHVM_RC_INT_SAME(MSG_NOSIGNAL);


    HHVM_RC_INT_SAME(MSG_DONTWAIT);


    HHVM_RC_INT_SAME(MSG_MORE);


    HHVM_RC_INT_SAME(MSG_WAITFORONE);


    HHVM_RC_INT_SAME(MSG_CMSG_CLOEXEC);


    HHVM_RC_INT_SAME(SO_DEBUG);
    HHVM_RC_INT_SAME(SO_REUSEADDR);

    HHVM_RC_INT_SAME(SO_REUSEPORT);

    HHVM_RC_INT_SAME(SO_KEEPALIVE);
    HHVM_RC_INT_SAME(SO_DONTROUTE);
    HHVM_RC_INT_SAME(SO_LINGER);
    HHVM_RC_INT_SAME(SO_BROADCAST);
    HHVM_RC_INT_SAME(SO_OOBINLINE);
    HHVM_RC_INT_SAME(SO_SNDBUF);
    HHVM_RC_INT_SAME(SO_RCVBUF);
    HHVM_RC_INT_SAME(SO_SNDLOWAT);
    HHVM_RC_INT_SAME(SO_RCVLOWAT);
    HHVM_RC_INT_SAME(SO_SNDTIMEO);
    HHVM_RC_INT_SAME(SO_RCVTIMEO);
    HHVM_RC_INT_SAME(SO_TYPE);

    HHVM_RC_INT_SAME(SO_FAMILY);

    HHVM_RC_INT_SAME(SO_ERROR);

    HHVM_RC_INT_SAME(SO_BINDTODEVICE);

    HHVM_RC_INT_SAME(SOL_SOCKET);
    HHVM_RC_INT_SAME(SOMAXCONN);

    HHVM_RC_INT_SAME(TCP_NODELAY);

    HHVM_RC_INT_SAME(PHP_NORMAL_READ);
    HHVM_RC_INT_SAME(PHP_BINARY_READ);

    

    HHVM_RC_INT_SAME(IP_MULTICAST_IF);
    HHVM_RC_INT_SAME(IP_MULTICAST_TTL);
    HHVM_RC_INT_SAME(IP_MULTICAST_LOOP);
    HHVM_RC_INT_SAME(IPV6_MULTICAST_IF);
    HHVM_RC_INT_SAME(IPV6_MULTICAST_HOPS);
    HHVM_RC_INT_SAME(IPV6_MULTICAST_LOOP);
    HHVM_RC_INT_SAME(IPPROTO_IP);
    HHVM_RC_INT_SAME(IPPROTO_IPV6);

    HHVM_RC_INT(SOL_TCP, IPPROTO_TCP);
    HHVM_RC_INT(SOL_UDP, IPPROTO_UDP);

    HHVM_RC_INT_SAME(IPV6_UNICAST_HOPS);





    HHVM_FE(socket_create);
    HHVM_FE(socket_create_listen);
    HHVM_FE(socket_create_pair);
    HHVM_FE(socket_get_option);
    HHVM_FE(socket_getpeername);
    HHVM_FE(socket_getsockname);
    HHVM_FE(socket_set_block);
    HHVM_FE(socket_set_nonblock);
    HHVM_FE(socket_set_option);
    HHVM_FE(socket_connect);
    HHVM_FE(socket_bind);
    HHVM_FE(socket_listen);
    HHVM_FE(socket_select);
    HHVM_FE(socket_server);
    HHVM_FE(socket_accept);
    HHVM_FE(socket_read);
    HHVM_FE(socket_write);
    HHVM_FE(socket_send);
    HHVM_FE(socket_sendto);
    HHVM_FE(socket_recv);
    HHVM_FE(socket_recvfrom);
    HHVM_FE(socket_shutdown);
    HHVM_FE(socket_close);
    HHVM_FE(socket_strerror);
    HHVM_FE(socket_last_error);
    HHVM_FE(socket_clear_error);
    HHVM_FE(getaddrinfo);

    loadSystemlib();
  }
} s_sockets_extension;


}
