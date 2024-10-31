


























typedef STRUCT_INT Inttype;


typedef unsigned STRUCT_INT Uinttype;









struct cD {
  char c;
  double d;
};











static union {
  int dummy;
  char endian;
} const native = {1};


typedef struct Header {
  int endian;
  int align;
} Header;


static int getnum (const char **fmt, int df) {
  if (!isdigit(**fmt))  
    return df;  
  else {
    int a = 0;
    do {
      a = a*10 + *((*fmt)++) - '0';
    } while (isdigit(**fmt));
    return a;
  }
}






static size_t optsize (lua_State *L, char opt, const char **fmt) {
  switch (opt) {
    case 'B': case 'b': return sizeof(char);
    case 'H': case 'h': return sizeof(short);
    case 'L': case 'l': return sizeof(long);
    case 'T': return sizeof(size_t);
    case 'f':  return sizeof(float);
    case 'd':  return sizeof(double);
    case 'x': return 1;
    case 'c': return getnum(fmt, 1);
    case 'i': case 'I': {
      int sz = getnum(fmt, sizeof(int));
      if (sz > MAXINTSIZE)
        luaL_error(L, "integral size %d is larger than limit of %d", sz, MAXINTSIZE);
      return sz;
    }
    default: return 0;  
  }
}



static int gettoalign (size_t len, Header *h, int opt, size_t size) {
  if (size == 0 || opt == 'c') return 0;
  if (size > (size_t)h->align)
    size = h->align;  
  return (size - (len & (size - 1))) & (size - 1);
}



static void controloptions (lua_State *L, int opt, const char **fmt, Header *h) {
  switch (opt) {
    case  ' ': return;  
    case '>': h->endian = BIG; return;
    case '<': h->endian = LITTLE; return;
    case '!': {
      int a = getnum(fmt, MAXALIGN);
      if (!isp2(a))
        luaL_error(L, "alignment %d is not a power of 2", a);
      h->align = a;
      return;
    }
    default: {
      const char *msg = lua_pushfstring(L, "invalid format option '%c'", opt);
      luaL_argerror(L, 1, msg);
    }
  }
}


static void putinteger (lua_State *L, luaL_Buffer *b, int arg, int endian, int size) {
  lua_Number n = luaL_checknumber(L, arg);
  Uinttype value;
  char buff[MAXINTSIZE];
  if (n < 0)
    value = (Uinttype)(Inttype)n;
  else value = (Uinttype)n;
  if (endian == LITTLE) {
    int i;
    for (i = 0; i < size; i++) {
      buff[i] = (value & 0xff);
      value >>= 8;
    }
  }
  else {
    int i;
    for (i = size - 1; i >= 0; i--) {
      buff[i] = (value & 0xff);
      value >>= 8;
    }
  }
  luaL_addlstring(b, buff, size);
}


static void correctbytes (char *b, int size, int endian) {
  if (endian != native.endian) {
    int i = 0;
    while (i < --size) {
      char temp = b[i];
      b[i++] = b[size];
      b[size] = temp;
    }
  }
}


static int b_pack (lua_State *L) {
  luaL_Buffer b;
  const char *fmt = luaL_checkstring(L, 1);
  Header h;
  int arg = 2;
  size_t totalsize = 0;
  defaultoptions(&h);
  lua_pushnil(L);  
  luaL_buffinit(L, &b);
  while (*fmt != '\0') {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    int toalign = gettoalign(totalsize, &h, opt, size);
    totalsize += toalign;
    while (toalign-- > 0) luaL_addchar(&b, '\0');
    switch (opt) {
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'T': case 'i': case 'I': {  
        putinteger(L, &b, arg++, h.endian, size);
        break;
      }
      case 'x': {
        luaL_addchar(&b, '\0');
        break;
      }
      case 'f': {
        float f = (float)luaL_checknumber(L, arg++);
        correctbytes((char *)&f, size, h.endian);
        luaL_addlstring(&b, (char *)&f, size);
        break;
      }
      case 'd': {
        double d = luaL_checknumber(L, arg++);
        correctbytes((char *)&d, size, h.endian);
        luaL_addlstring(&b, (char *)&d, size);
        break;
      }
      case 'c': case 's': {
        size_t l;
        const char *s = luaL_checklstring(L, arg++, &l);
        if (size == 0) size = l;
        luaL_argcheck(L, l >= (size_t)size, arg, "string too short");
        luaL_addlstring(&b, s, size);
        if (opt == 's') {
          luaL_addchar(&b, '\0');  
          size++;
        }
        break;
      }
      default: controloptions(L, opt, &fmt, &h);
    }
    totalsize += size;
  }
  luaL_pushresult(&b);
  return 1;
}


static lua_Number getinteger (const char *buff, int endian, int issigned, int size) {
  Uinttype l = 0;
  int i;
  if (endian == BIG) {
    for (i = 0; i < size; i++) {
      l <<= 8;
      l |= (Uinttype)(unsigned char)buff[i];
    }
  }
  else {
    for (i = size - 1; i >= 0; i--) {
      l <<= 8;
      l |= (Uinttype)(unsigned char)buff[i];
    }
  }
  if (!issigned)
    return (lua_Number)l;
  else {  
    Uinttype mask = (Uinttype)(~((Uinttype)0)) << (size*8 - 1);
    if (l & mask)  
      l |= mask;  
    return (lua_Number)(Inttype)l;
  }
}


static int b_unpack (lua_State *L) {
  Header h;
  const char *fmt = luaL_checkstring(L, 1);
  size_t ld;
  const char *data = luaL_checklstring(L, 2, &ld);
  size_t pos = luaL_optinteger(L, 3, 1);
  luaL_argcheck(L, pos > 0, 3, "offset must be 1 or greater");
  pos--; 
  int n = 0;  
  defaultoptions(&h);
  while (*fmt) {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    pos += gettoalign(pos, &h, opt, size);
    luaL_argcheck(L, size <= ld && pos <= ld - size, 2, "data string too short");
    
    luaL_checkstack(L, 2, "too many results");
    switch (opt) {
      case 'b': case 'B': case 'h': case 'H':
      case 'l': case 'L': case 'T': case 'i':  case 'I': {  
        int issigned = islower(opt);
        lua_Number res = getinteger(data+pos, h.endian, issigned, size);
        lua_pushnumber(L, res); n++;
        break;
      }
      case 'x': {
        break;
      }
      case 'f': {
        float f;
        memcpy(&f, data+pos, size);
        correctbytes((char *)&f, sizeof(f), h.endian);
        lua_pushnumber(L, f); n++;
        break;
      }
      case 'd': {
        double d;
        memcpy(&d, data+pos, size);
        correctbytes((char *)&d, sizeof(d), h.endian);
        lua_pushnumber(L, d); n++;
        break;
      }
      case 'c': {
        if (size == 0) {
          if (n == 0 || !lua_isnumber(L, -1))
            luaL_error(L, "format 'c0' needs a previous size");
          size = lua_tonumber(L, -1);
          lua_pop(L, 1); n--;
          luaL_argcheck(L, size <= ld && pos <= ld - size, 2, "data string too short");
        }
        lua_pushlstring(L, data+pos, size); n++;
        break;
      }
      case 's': {
        const char *e = (const char *)memchr(data+pos, '\0', ld - pos);
        if (e == NULL)
          luaL_error(L, "unfinished string in data");
        size = (e - (data+pos)) + 1;
        lua_pushlstring(L, data+pos, size - 1); n++;
        break;
      }
      default: controloptions(L, opt, &fmt, &h);
    }
    pos += size;
  }
  lua_pushinteger(L, pos + 1);  
  return n + 1;
}


static int b_size (lua_State *L) {
  Header h;
  const char *fmt = luaL_checkstring(L, 1);
  size_t pos = 0;
  defaultoptions(&h);
  while (*fmt) {
    int opt = *fmt++;
    size_t size = optsize(L, opt, &fmt);
    pos += gettoalign(pos, &h, opt, size);
    if (opt == 's')
      luaL_argerror(L, 1, "option 's' has no fixed size");
    else if (opt == 'c' && size == 0)
      luaL_argerror(L, 1, "option 'c0' has no fixed size");
    if (!isalnum(opt))
      controloptions(L, opt, &fmt, &h);
    pos += size;
  }
  lua_pushinteger(L, pos);
  return 1;
}





static const struct luaL_Reg thislib[] = {
  {"pack", b_pack}, {"unpack", b_unpack}, {"size", b_size}, {NULL, NULL}


};


LUALIB_API int luaopen_struct (lua_State *L);

LUALIB_API int luaopen_struct (lua_State *L) {
  luaL_register(L, "struct", thislib);
  return 1;
}




