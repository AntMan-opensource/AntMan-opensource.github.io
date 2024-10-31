







void nghttp2_put_uint16be(uint8_t *buf, uint16_t n) {
  uint16_t x = htons(n);
  memcpy(buf, &x, sizeof(uint16_t));
}

void nghttp2_put_uint32be(uint8_t *buf, uint32_t n) {
  uint32_t x = htonl(n);
  memcpy(buf, &x, sizeof(uint32_t));
}

uint16_t nghttp2_get_uint16(const uint8_t *data) {
  uint16_t n;
  memcpy(&n, data, sizeof(uint16_t));
  return ntohs(n);
}

uint32_t nghttp2_get_uint32(const uint8_t *data) {
  uint32_t n;
  memcpy(&n, data, sizeof(uint32_t));
  return ntohl(n);
}


static const uint8_t DOWNCASE_TBL[] = {
    0 ,   1 ,   2 ,   3 , 4 ,   5 ,   6 ,   7 , 8 ,   9 ,   10 ,  11 , 12 ,  13 ,  14 ,  15 , 16 ,  17 ,  18 ,  19 , 20 ,  21 ,  22 ,  23 , 24 ,  25 ,  26 ,  27 , 28 ,  29 ,  30 ,  31 , 32 ,  33 ,  34 ,  35 , 36 ,  37 ,  38 ,  39 , 40 ,  41 ,  42 ,  43 , 44 ,  45 ,  46 ,  47 , 48 ,  49 ,  50 ,  51 , 52 ,  53 ,  54 ,  55 , 56 ,  57 ,  58 ,  59 , 60 ,  61 ,  62 ,  63 , 64 ,  97 ,  98 ,  99 , 100 , 101 , 102 , 103 , 104 , 105 , 106 , 107 , 108 , 109 , 110 , 111 , 112 , 113 , 114 , 115 , 116 , 117 , 118 , 119 , 120 , 121 , 122 , 91 , 92 ,  93 ,  94 ,  95 , 96 ,  97 ,  98 ,  99 , 100 , 101 , 102 , 103 , 104 , 105 , 106 , 107 , 108 , 109 , 110 , 111 , 112 , 113 , 114 , 115 , 116 , 117 , 118 , 119 , 120 , 121 , 122 , 123 , 124 , 125 , 126 , 127 , 128 , 129 , 130 , 131 , 132 , 133 , 134 , 135 , 136 , 137 , 138 , 139 , 140 , 141 , 142 , 143 , 144 , 145 , 146 , 147 , 148 , 149 , 150 , 151 , 152 , 153 , 154 , 155 , 156 , 157 , 158 , 159 , 160 , 161 , 162 , 163 , 164 , 165 , 166 , 167 , 168 , 169 , 170 , 171 , 172 , 173 , 174 , 175 , 176 , 177 , 178 , 179 , 180 , 181 , 182 , 183 , 184 , 185 , 186 , 187 , 188 , 189 , 190 , 191 , 192 , 193 , 194 , 195 , 196 , 197 , 198 , 199 , 200 , 201 , 202 , 203 , 204 , 205 , 206 , 207 , 208 , 209 , 210 , 211 , 212 , 213 , 214 , 215 , 216 , 217 , 218 , 219 , 220 , 221 , 222 , 223 , 224 , 225 , 226 , 227 , 228 , 229 , 230 , 231 , 232 , 233 , 234 , 235 , 236 , 237 , 238 , 239 , 240 , 241 , 242 , 243 , 244 , 245 , 246 , 247 , 248 , 249 , 250 , 251 , 252 , 253 , 254 , 255 , };
































































void nghttp2_downcase(uint8_t *s, size_t len) {
  size_t i;
  for (i = 0; i < len; ++i) {
    s[i] = DOWNCASE_TBL[s[i]];
  }
}


int nghttp2_adjust_local_window_size(int32_t *local_window_size_ptr, int32_t *recv_window_size_ptr, int32_t *recv_reduction_ptr, int32_t *delta_ptr) {


  if (*delta_ptr > 0) {
    int32_t recv_reduction_delta;
    int32_t delta;
    int32_t new_recv_window_size = nghttp2_max(0, *recv_window_size_ptr) - *delta_ptr;

    if (new_recv_window_size >= 0) {
      *recv_window_size_ptr = new_recv_window_size;
      return 0;
    }

    delta = -new_recv_window_size;

    
    if (*local_window_size_ptr > NGHTTP2_MAX_WINDOW_SIZE - delta) {
      return NGHTTP2_ERR_FLOW_CONTROL;
    }
    *local_window_size_ptr += delta;
    
    recv_reduction_delta = nghttp2_min(*recv_reduction_ptr, delta);
    *recv_reduction_ptr -= recv_reduction_delta;
    if (*recv_window_size_ptr < 0) {
      *recv_window_size_ptr += recv_reduction_delta;
    } else {
      
      *recv_window_size_ptr = recv_reduction_delta;
    }
    
    *delta_ptr -= recv_reduction_delta;

    return 0;
  }

  if (*local_window_size_ptr + *delta_ptr < 0 || *recv_window_size_ptr < INT32_MIN - *delta_ptr || *recv_reduction_ptr > INT32_MAX + *delta_ptr) {

    return NGHTTP2_ERR_FLOW_CONTROL;
  }
  
  *local_window_size_ptr += *delta_ptr;
  *recv_window_size_ptr += *delta_ptr;
  *recv_reduction_ptr -= *delta_ptr;
  *delta_ptr = 0;

  return 0;
}

int nghttp2_increase_local_window_size(int32_t *local_window_size_ptr, int32_t *recv_window_size_ptr, int32_t *recv_reduction_ptr, int32_t *delta_ptr) {


  int32_t recv_reduction_delta;
  int32_t delta;

  delta = *delta_ptr;

  assert(delta >= 0);

  
  if (*local_window_size_ptr > NGHTTP2_MAX_WINDOW_SIZE - delta) {
    return NGHTTP2_ERR_FLOW_CONTROL;
  }

  *local_window_size_ptr += delta;
  
  recv_reduction_delta = nghttp2_min(*recv_reduction_ptr, delta);
  *recv_reduction_ptr -= recv_reduction_delta;

  *recv_window_size_ptr += recv_reduction_delta;

  
  *delta_ptr -= recv_reduction_delta;

  return 0;
}

int nghttp2_should_send_window_update(int32_t local_window_size, int32_t recv_window_size) {
  return recv_window_size > 0 && recv_window_size >= local_window_size / 2;
}

const char *nghttp2_strerror(int error_code) {
  switch (error_code) {
  case 0:
    return "Success";
  case NGHTTP2_ERR_INVALID_ARGUMENT:
    return "Invalid argument";
  case NGHTTP2_ERR_BUFFER_ERROR:
    return "Out of buffer space";
  case NGHTTP2_ERR_UNSUPPORTED_VERSION:
    return "Unsupported SPDY version";
  case NGHTTP2_ERR_WOULDBLOCK:
    return "Operation would block";
  case NGHTTP2_ERR_PROTO:
    return "Protocol error";
  case NGHTTP2_ERR_INVALID_FRAME:
    return "Invalid frame octets";
  case NGHTTP2_ERR_EOF:
    return "EOF";
  case NGHTTP2_ERR_DEFERRED:
    return "Data transfer deferred";
  case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
    return "No more Stream ID available";
  case NGHTTP2_ERR_STREAM_CLOSED:
    return "Stream was already closed or invalid";
  case NGHTTP2_ERR_STREAM_CLOSING:
    return "Stream is closing";
  case NGHTTP2_ERR_STREAM_SHUT_WR:
    return "The transmission is not allowed for this stream";
  case NGHTTP2_ERR_INVALID_STREAM_ID:
    return "Stream ID is invalid";
  case NGHTTP2_ERR_INVALID_STREAM_STATE:
    return "Invalid stream state";
  case NGHTTP2_ERR_DEFERRED_DATA_EXIST:
    return "Another DATA frame has already been deferred";
  case NGHTTP2_ERR_START_STREAM_NOT_ALLOWED:
    return "request HEADERS is not allowed";
  case NGHTTP2_ERR_GOAWAY_ALREADY_SENT:
    return "GOAWAY has already been sent";
  case NGHTTP2_ERR_INVALID_HEADER_BLOCK:
    return "Invalid header block";
  case NGHTTP2_ERR_INVALID_STATE:
    return "Invalid state";
  case NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE:
    return "The user callback function failed due to the temporal error";
  case NGHTTP2_ERR_FRAME_SIZE_ERROR:
    return "The length of the frame is invalid";
  case NGHTTP2_ERR_HEADER_COMP:
    return "Header compression/decompression error";
  case NGHTTP2_ERR_FLOW_CONTROL:
    return "Flow control error";
  case NGHTTP2_ERR_INSUFF_BUFSIZE:
    return "Insufficient buffer size given to function";
  case NGHTTP2_ERR_PAUSE:
    return "Callback was paused by the application";
  case NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS:
    return "Too many inflight SETTINGS";
  case NGHTTP2_ERR_PUSH_DISABLED:
    return "Server push is disabled by peer";
  case NGHTTP2_ERR_DATA_EXIST:
    return "DATA or HEADERS frame has already been submitted for the stream";
  case NGHTTP2_ERR_SESSION_CLOSING:
    return "The current session is closing";
  case NGHTTP2_ERR_HTTP_HEADER:
    return "Invalid HTTP header field was received";
  case NGHTTP2_ERR_HTTP_MESSAGING:
    return "Violation in HTTP messaging rule";
  case NGHTTP2_ERR_REFUSED_STREAM:
    return "Stream was refused";
  case NGHTTP2_ERR_INTERNAL:
    return "Internal error";
  case NGHTTP2_ERR_CANCEL:
    return "Cancel";
  case NGHTTP2_ERR_SETTINGS_EXPECTED:
    return "When a local endpoint expects to receive SETTINGS frame, it " "receives an other type of frame";
  case NGHTTP2_ERR_NOMEM:
    return "Out of memory";
  case NGHTTP2_ERR_CALLBACK_FAILURE:
    return "The user callback function failed";
  case NGHTTP2_ERR_BAD_CLIENT_MAGIC:
    return "Received bad client magic byte string";
  case NGHTTP2_ERR_FLOODED:
    return "Flooding was detected in this HTTP/2 session, and it must be " "closed";
  default:
    return "Unknown error code";
  }
}


static const int VALID_HD_NAME_CHARS[] = {
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 , 0 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 1 , 1 , 0 , 1 , 1 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 1 , 0 , 1 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 };
































































int nghttp2_check_header_name(const uint8_t *name, size_t len) {
  const uint8_t *last;
  if (len == 0) {
    return 0;
  }
  if (*name == ':') {
    if (len == 1) {
      return 0;
    }
    ++name;
    --len;
  }
  for (last = name + len; name != last; ++name) {
    if (!VALID_HD_NAME_CHARS[*name]) {
      return 0;
    }
  }
  return 1;
}


static const int VALID_HD_VALUE_CHARS[] = {
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 };
































































int nghttp2_check_header_value(const uint8_t *value, size_t len) {
  const uint8_t *last;
  for (last = value + len; value != last; ++value) {
    if (!VALID_HD_VALUE_CHARS[*value]) {
      return 0;
    }
  }
  return 1;
}


static char VALID_AUTHORITY_CHARS[] = {
    0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 , 0 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 1 , 0 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 1 , 0 , 1 , 0 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 1 , 0 , 0 , 0 , 1 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 };
































































int nghttp2_check_authority(const uint8_t *value, size_t len) {
  const uint8_t *last;
  for (last = value + len; value != last; ++value) {
    if (!VALID_AUTHORITY_CHARS[*value]) {
      return 0;
    }
  }
  return 1;
}

uint8_t *nghttp2_cpymem(uint8_t *dest, const void *src, size_t len) {
  if (len == 0) {
    return dest;
  }

  memcpy(dest, src, len);

  return dest + len;
}

const char *nghttp2_http2_strerror(uint32_t error_code) {
  switch (error_code) {
  case NGHTTP2_NO_ERROR:
    return "NO_ERROR";
  case NGHTTP2_PROTOCOL_ERROR:
    return "PROTOCOL_ERROR";
  case NGHTTP2_INTERNAL_ERROR:
    return "INTERNAL_ERROR";
  case NGHTTP2_FLOW_CONTROL_ERROR:
    return "FLOW_CONTROL_ERROR";
  case NGHTTP2_SETTINGS_TIMEOUT:
    return "SETTINGS_TIMEOUT";
  case NGHTTP2_STREAM_CLOSED:
    return "STREAM_CLOSED";
  case NGHTTP2_FRAME_SIZE_ERROR:
    return "FRAME_SIZE_ERROR";
  case NGHTTP2_REFUSED_STREAM:
    return "REFUSED_STREAM";
  case NGHTTP2_CANCEL:
    return "CANCEL";
  case NGHTTP2_COMPRESSION_ERROR:
    return "COMPRESSION_ERROR";
  case NGHTTP2_CONNECT_ERROR:
    return "CONNECT_ERROR";
  case NGHTTP2_ENHANCE_YOUR_CALM:
    return "ENHANCE_YOUR_CALM";
  case NGHTTP2_INADEQUATE_SECURITY:
    return "INADEQUATE_SECURITY";
  case NGHTTP2_HTTP_1_1_REQUIRED:
    return "HTTP_1_1_REQUIRED";
  default:
    return "unknown";
  }
}
