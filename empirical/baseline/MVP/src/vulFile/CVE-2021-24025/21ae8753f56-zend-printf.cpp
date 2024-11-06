














namespace HPHP {




typedef enum {
  LM_STD = 0, LM_INTMAX_T, LM_PTRDIFF_T, LM_LONG_LONG, LM_SIZE_T, LM_LONG, LM_LONG_DOUBLE } length_modifier_e;







typedef enum {
  NO = 0, YES = 1 } boolean_e;























typedef int64_t wide_int;
typedef uint64_t u_wide_int;






static const char* s_null = "(null)";








} 



namespace HPHP {








static char * __cvt(double value, int ndigit, int *decpt, int *sign, int fmode, int pad) {
  register char *s = nullptr;
  char *p, *rve, c;
  size_t siz;

  if (ndigit < 0) {
    siz = -ndigit + 1;
  } else {
    siz = ndigit + 1;
  }

  
  if (value == 0.0) {
    *decpt = 1 - fmode; 
    *sign = 0;
    if ((rve = s = (char *)malloc(ndigit?siz:2)) == nullptr) {
      return(nullptr);
    }
    *rve++ = '0';
    *rve = '\0';
    if (!ndigit) {
      return(s);
    }
  } else {
    p = zend_dtoa(value, fmode + 2, ndigit, decpt, sign, &rve);
    if (*decpt == 9999) {
      
      *decpt = 0;
      c = *p;
      zend_freedtoa(p);
      return strdup(c == 'I' ? "INF" : "NAN");
    }
    
    if (pad && fmode) {
      siz += *decpt;
    }
    if ((s = (char *)malloc(siz+1)) == nullptr) {
      zend_freedtoa(p);
      return(nullptr);
    }
    (void)string_copy(s, p, siz);
    rve = s + (rve - p);
    zend_freedtoa(p);
  }

  
  if (pad) {
    siz -= rve - s;
    while (--siz) {
      *rve++ = '0';
    }
    *rve = '\0';
  }

  return(s);
}

static inline char *php_ecvt(double value, int ndigit, int *decpt, int *sign) {
  return(__cvt(value, ndigit, decpt, sign, 0, 1));
}

static inline char *php_fcvt(double value, int ndigit, int *decpt, int *sign) {
  return(__cvt(value, ndigit, decpt, sign, 1, 1));
}

char *php_gcvt(double value, int ndigit, char dec_point, char exponent, char *buf) {
  char *digits, *dst, *src;
  int i, decpt, sign;

  digits = zend_dtoa(value, 2, ndigit, &decpt, &sign, nullptr);
  if (decpt == 9999) {
    
    snprintf(buf, ndigit + 1, "%s%s", (sign && *digits == 'I') ? "-" : "", *digits == 'I' ? "INF" : "NAN");
    zend_freedtoa(digits);
    return (buf);
  }

  dst = buf;
  if (sign) {
    *dst++ = '-';
  }

  if ((decpt >= 0 && decpt > ndigit) || decpt < -3) { 
    
    if (--decpt < 0) {
      sign = 1;
      decpt = -decpt;
    } else {
      sign = 0;
    }
    src = digits;
    *dst++ = *src++;
    *dst++ = dec_point;
    if (*src == '\0') {
      *dst++ = '0';
    } else {
      do {
        *dst++ = *src++;
      } while (*src != '\0');
    }
    *dst++ = exponent;
    if (sign) {
      *dst++ = '-';
    } else {
      *dst++ = '+';
    }
    if (decpt < 10) {
      *dst++ = '0' + decpt;
      *dst = '\0';
    } else {
      
      for (sign = decpt, i = 0; (sign /= 10) != 0; i++)
        continue;
      dst[i + 1] = '\0';
      while (decpt != 0) {
        dst[i--] = '0' + decpt % 10;
        decpt /= 10;
      }
    }
  } else if (decpt < 0) {
    
    *dst++ = '0';   
    *dst++ = dec_point;
    do {
      *dst++ = '0';
    } while (++decpt < 0);
    src = digits;
    while (*src != '\0') {
      *dst++ = *src++;
    }
    *dst = '\0';
  } else {
    
    for (i = 0, src = digits; i < decpt; i++) {
      if (*src != '\0') {
        *dst++ = *src++;
      } else {
        *dst++ = '0';
      }
    }
    if (*src != '\0') {
      if (src == digits) {
        *dst++ = '0';   
      }
      *dst++ = dec_point;
      for (i = decpt; digits[i] != '\0'; i++) {
        *dst++ = digits[i];
      }
    }
    *dst = '\0';
  }
  zend_freedtoa(digits);
  return (buf);
}







char * ap_php_conv_p2(register uint64_t num, register int nbits, char format, char *buf_end, register int *len)
{
  register int mask = (1 << nbits) - 1;
  register char *p = buf_end;
  static char low_digits[] = "0123456789abcdef";
  static char upper_digits[] = "0123456789ABCDEF";
  register char *digits = (format == 'X') ? upper_digits : low_digits;

  do {
    *--p = digits[num & mask];
    num >>= nbits;
  }
  while (num);

  *len = buf_end - p;
  return (p);
}


char * ap_php_conv_10(register int64_t num, register bool is_unsigned, register int * is_negative, char *buf_end, register int *len) {

  register char *p = buf_end;
  register uint64_t magnitude;

  if (is_unsigned) {
    magnitude = (uint64_t) num;
    *is_negative = 0;
  } else {
    *is_negative = (num < 0);

    
    if (*is_negative) {
      int64_t t = num + 1;
      magnitude = ((uint64_t) - t) + 1;
    } else {
      magnitude = (uint64_t) num;
    }
  }

  
  do {
    register uint64_t new_magnitude = magnitude / 10;

    *--p = (char)(magnitude - new_magnitude * 10 + '0');
    magnitude = new_magnitude;
  }
  while (magnitude);

  *len = buf_end - p;
  return (p);
}



char * php_conv_fp(register char format, register double num, bool add_dp, int precision, char dec_point, int *is_negative, char *buf, int *len) {

  register char *s = buf;
  register char *p, *p_orig;
  int decimal_point;

  if (precision >= NDIG - 1) {
    precision = NDIG - 2;
  }

  if (format == 'F') {
    p_orig = p = php_fcvt(num, precision, &decimal_point, is_negative);
  } else { 
    p_orig = p = php_ecvt(num, precision + 1, &decimal_point, is_negative);
  }

  
  if (isalpha((int)*p)) {
    *len = strlen(p);
    memcpy(buf, p, *len + 1);
    *is_negative = 0;
    free(p_orig);
    return (buf);
  }
  if (format == 'F') {
    if (decimal_point <= 0) {
      if (num != 0 || precision > 0) {
        *s++ = '0';
        if (precision > 0) {
          *s++ = dec_point;
          while (decimal_point++ < 0) {
            *s++ = '0';
          }
        } else if (add_dp) {
          *s++ = dec_point;
        }
      }
    } else {
      int addz = decimal_point >= NDIG ? decimal_point - NDIG + 1 : 0;
      decimal_point -= addz;
      while (decimal_point-- > 0) {
        *s++ = *p++;
      }
      while (addz-- > 0) {
        *s++ = '0';
      }
      if (precision > 0 || add_dp) {
        *s++ = dec_point;
      }
    }
  } else {
    *s++ = *p++;
    if (precision > 0 || add_dp) {
      *s++ = '.';
    }
  }

  
  while (*p) {
    *s++ = *p++;
  }

  if (format != 'F') {
    char temp[EXPONENT_LENGTH]; 
    int t_len;
    int exponent_is_negative;

    *s++ = format; 
    decimal_point--;
    if (decimal_point != 0) {
      p = ap_php_conv_10((int64_t) decimal_point, false, &exponent_is_negative, &temp[EXPONENT_LENGTH], &t_len);

      *s++ = exponent_is_negative ? '-' : '+';

      
      while (t_len--) {
        *s++ = *p++;
      }
    } else {
      *s++ = '+';
      *s++ = '0';
    }
  }
  *len = s - buf;
  free(p_orig);
  return (buf);
}



inline static void appendchar(char **buffer, int *pos, int *size, char add) {
  if ((*pos + 1) >= *size) {
    *size <<= 1;
    *buffer = (char*)realloc(*buffer, *size);
  }
  (*buffer)[(*pos)++] = add;
}

inline static void appendsimplestring(char **buffer, int *pos, int *size, const char *add, int len) {
  int req_size = *pos + len;

  if (req_size > *size) {
    while (req_size > *size) {
      *size <<= 1;
    }
    *buffer = (char *)realloc(*buffer, *size);
  }
  memcpy(&(*buffer)[*pos], add, len);
  *pos += len;
}


static int xbuf_format_converter(char **outbuf, const char *fmt, va_list ap)
{
  register char *s = nullptr;
  char *q;
  int s_len;

  register int min_width = 0;
  int precision = 0;
  enum {
    LEFT, RIGHT } adjust;
  char pad_char;
  char prefix_char;

  double fp_num;
  wide_int i_num = (wide_int) 0;
  u_wide_int ui_num;

  char num_buf[NUM_BUF_SIZE];
  char char_buf[2];      


  struct lconv *lconv = nullptr;


  
  length_modifier_e modifier;
  boolean_e alternate_form;
  boolean_e print_sign;
  boolean_e print_blank;
  boolean_e adjust_precision;
  boolean_e adjust_width;
  int is_negative;

  int size = 240;
  char *result = (char *)malloc(size);
  int outpos = 0;

  while (*fmt) {
    if (*fmt != '%') {
      appendchar(&result, &outpos, &size, *fmt);
    } else {
      
      adjust = RIGHT;
      alternate_form = print_sign = print_blank = NO;
      pad_char = ' ';
      prefix_char = NUL;

      fmt++;

      
      if (isascii((int)*fmt) && !islower((int)*fmt)) {
        
        for (;; fmt++) {
          if (*fmt == '-')
            adjust = LEFT;
          else if (*fmt == '+')
            print_sign = YES;
          else if (*fmt == '#')
            alternate_form = YES;
          else if (*fmt == ' ')
            print_blank = YES;
          else if (*fmt == '0')
            pad_char = '0';
          else break;
        }

        
        if (isdigit((int)*fmt)) {
          STR_TO_DEC(fmt, min_width);
          adjust_width = YES;
        } else if (*fmt == '*') {
          min_width = va_arg(ap, int);
          fmt++;
          adjust_width = YES;
          if (min_width < 0) {
            adjust = LEFT;
            min_width = -min_width;
          }
        } else adjust_width = NO;

        
        if (*fmt == '.') {
          adjust_precision = YES;
          fmt++;
          if (isdigit((int)*fmt)) {
            STR_TO_DEC(fmt, precision);
          } else if (*fmt == '*') {
            precision = va_arg(ap, int);
            fmt++;
            if (precision < 0)
              precision = 0;
          } else precision = 0;
        } else adjust_precision = NO;
      } else adjust_precision = adjust_width = NO;

      
      switch (*fmt) {
        case 'L':
          fmt++;
          modifier = LM_LONG_DOUBLE;
          break;
        case 'I':
          fmt++;

          if (*fmt == '6' && *(fmt+1) == '4') {
            fmt += 2;
            modifier = LM_LONG_LONG;
          } else  if (*fmt == '3' && *(fmt+1) == '2') {

              fmt += 2;
              modifier = LM_LONG;
            } else {

              modifier = LM_LONG_LONG;

              modifier = LM_LONG;

            }
          break;
        case 'l':
          fmt++;

          if (*fmt == 'l') {
            fmt++;
            modifier = LM_LONG_LONG;
          } else  modifier = LM_LONG;

          break;
        case 'z':
          fmt++;
          modifier = LM_SIZE_T;
          break;
        case 'j':
          fmt++;

          modifier = LM_INTMAX_T;

          modifier = LM_SIZE_T;

          break;
        case 't':
          fmt++;

          modifier = LM_PTRDIFF_T;

          modifier = LM_SIZE_T;

          break;
        case 'h':
          fmt++;
          if (*fmt == 'h') {
            fmt++;
          }
          
        default:
          modifier = LM_STD;
          break;
      }

      
      switch (*fmt) {
        case 'u':
          switch(modifier) {
            default:
              i_num = (wide_int) va_arg(ap, unsigned int);
              break;
            case LM_LONG_DOUBLE:
              goto fmt_error;
            case LM_LONG:
              i_num = (wide_int) va_arg(ap, unsigned long int);
              break;
            case LM_SIZE_T:
              i_num = (wide_int) va_arg(ap, size_t);
              break;

            case LM_LONG_LONG:
              i_num = (wide_int) va_arg(ap, u_wide_int);
              break;


            case LM_INTMAX_T:
              i_num = (wide_int) va_arg(ap, uintmax_t);
              break;


            case LM_PTRDIFF_T:
              i_num = (wide_int) va_arg(ap, ptrdiff_t);
              break;

          }
          
        case 'd':
        case 'i':
          
          if ((*fmt) != 'u') {
            switch(modifier) {
              default:
                i_num = (wide_int) va_arg(ap, int);
                break;
              case LM_LONG_DOUBLE:
                goto fmt_error;
              case LM_LONG:
                i_num = (wide_int) va_arg(ap, long int);
                break;
              case LM_SIZE_T:

                i_num = (wide_int) va_arg(ap, ssize_t);

                i_num = (wide_int) va_arg(ap, size_t);

                break;

              case LM_LONG_LONG:
                i_num = (wide_int) va_arg(ap, wide_int);
                break;


              case LM_INTMAX_T:
                i_num = (wide_int) va_arg(ap, intmax_t);
                break;


              case LM_PTRDIFF_T:
                i_num = (wide_int) va_arg(ap, ptrdiff_t);
                break;

            }
          }
          s = ap_php_conv_10(i_num, (*fmt) == 'u', &is_negative, &num_buf[NUM_BUF_SIZE], &s_len);
          FIX_PRECISION(adjust_precision, precision, s, s_len);

          if (*fmt != 'u') {
            if (is_negative)
              prefix_char = '-';
            else if (print_sign)
              prefix_char = '+';
            else if (print_blank)
              prefix_char = ' ';
          }
          break;


        case 'o':
          switch(modifier) {
            default:
              ui_num = (u_wide_int) va_arg(ap, unsigned int);
              break;
            case LM_LONG_DOUBLE:
              goto fmt_error;
            case LM_LONG:
              ui_num = (u_wide_int) va_arg(ap, unsigned long int);
              break;
            case LM_SIZE_T:
              ui_num = (u_wide_int) va_arg(ap, size_t);
              break;

            case LM_LONG_LONG:
              ui_num = (u_wide_int) va_arg(ap, u_wide_int);
              break;


            case LM_INTMAX_T:
              ui_num = (u_wide_int) va_arg(ap, uintmax_t);
              break;


            case LM_PTRDIFF_T:
              ui_num = (u_wide_int) va_arg(ap, ptrdiff_t);
              break;

          }
          s = ap_php_conv_p2(ui_num, 3, *fmt, &num_buf[NUM_BUF_SIZE], &s_len);
          FIX_PRECISION(adjust_precision, precision, s, s_len);
          if (alternate_form && *s != '0') {
            *--s = '0';
            s_len++;
          }
          break;


        case 'x':
        case 'X':
          switch(modifier) {
            default:
              ui_num = (u_wide_int) va_arg(ap, unsigned int);
              break;
            case LM_LONG_DOUBLE:
              goto fmt_error;
            case LM_LONG:
              ui_num = (u_wide_int) va_arg(ap, unsigned long int);
              break;
            case LM_SIZE_T:
              ui_num = (u_wide_int) va_arg(ap, size_t);
              break;

            case LM_LONG_LONG:
              ui_num = (u_wide_int) va_arg(ap, u_wide_int);
              break;


            case LM_INTMAX_T:
              ui_num = (u_wide_int) va_arg(ap, uintmax_t);
              break;


            case LM_PTRDIFF_T:
              ui_num = (u_wide_int) va_arg(ap, ptrdiff_t);
              break;

          }
          s = ap_php_conv_p2(ui_num, 4, *fmt, &num_buf[NUM_BUF_SIZE], &s_len);
          FIX_PRECISION(adjust_precision, precision, s, s_len);
          if (alternate_form && i_num != 0) {
            *--s = *fmt;  
            *--s = '0';
            s_len += 2;
          }
          break;


        case 's':
        case 'v':
          s = va_arg(ap, char *);
          if (s != nullptr) {
            s_len = strlen(s);
            if (adjust_precision && precision < s_len)
              s_len = precision;
          } else {
            s = const_cast<char*>(s_null);
            s_len = S_NULL_LEN;
          }
          pad_char = ' ';
          break;


        case 'f':
        case 'F':
        case 'e':
        case 'E':
          switch(modifier) {
            case LM_LONG_DOUBLE:
              fp_num = (double) va_arg(ap, long double);
              break;
            case LM_STD:
              fp_num = va_arg(ap, double);
              break;
            default:
              goto fmt_error;
          }

          if (std::isnan(fp_num)) {
            s = const_cast<char*>("nan");
            s_len = 3;
          } else if (std::isinf(fp_num)) {
            s = const_cast<char*>("inf");
            s_len = 3;
          } else {

            if (!lconv) {
              lconv = localeconv();
            }

            s = php_conv_fp((*fmt == 'f')?'F':*fmt, fp_num, alternate_form, (adjust_precision == NO) ? FLOAT_DIGITS : precision, (*fmt == 'f')?LCONV_DECIMAL_POINT:'.', &is_negative, &num_buf[1], &s_len);


            if (is_negative)
              prefix_char = '-';
            else if (print_sign)
              prefix_char = '+';
            else if (print_blank)
              prefix_char = ' ';
          }
          break;


        case 'g':
        case 'k':
        case 'G':
        case 'H':
          switch(modifier) {
            case LM_LONG_DOUBLE:
              fp_num = (double) va_arg(ap, long double);
              break;
            case LM_STD:
              fp_num = va_arg(ap, double);
              break;
            default:
              goto fmt_error;
          }

          if (std::isnan(fp_num)) {
             s = const_cast<char*>("NAN");
             s_len = 3;
             break;
           } else if (std::isinf(fp_num)) {
             if (fp_num > 0) {
               s = const_cast<char*>("INF");
               s_len = 3;
             } else {
               s = const_cast<char*>("-INF");
               s_len = 4;
             }
             break;
           }

          if (adjust_precision == NO)
            precision = FLOAT_DIGITS;
          else if (precision == 0)
            precision = 1;
          

          if (!lconv) {
            lconv = localeconv();
          }

          s = php_gcvt(fp_num, precision, (*fmt=='H' || *fmt == 'k') ? '.' : LCONV_DECIMAL_POINT, (*fmt == 'G' || *fmt == 'H')?'E':'e', &num_buf[1]);

          if (*s == '-')
            prefix_char = *s++;
          else if (print_sign)
            prefix_char = '+';
          else if (print_blank)
            prefix_char = ' ';

          s_len = strlen(s);

          if (alternate_form && (q = strchr(s, '.')) == nullptr)
            s[s_len++] = '.';
          break;


        case 'c':
          char_buf[0] = (char) (va_arg(ap, int));
          s = &char_buf[0];
          s_len = 1;
          pad_char = ' ';
          break;


        case '%':
          char_buf[0] = '%';
          s = &char_buf[0];
          s_len = 1;
          pad_char = ' ';
          break;


        case 'n':
          *(va_arg(ap, int *)) = outpos;
          goto skip_output;

          
        case 'p':
          if (sizeof(char *) <= sizeof(u_wide_int)) {
            ui_num = (u_wide_int)((size_t) va_arg(ap, char *));
            s = ap_php_conv_p2(ui_num, 4, 'x', &num_buf[NUM_BUF_SIZE], &s_len);
            if (ui_num != 0) {
              *--s = 'x';
              *--s = '0';
              s_len += 2;
            }
          } else {
            s = const_cast<char*>("%p");
            s_len = 2;
          }
          pad_char = ' ';
          break;


        case NUL:
          
          continue;


fmt_error:
        throw Exception("Illegal length modifier specified '%c'", *fmt);

          
        default:
          char_buf[0] = '%';
          char_buf[1] = *fmt;
          s = char_buf;
          s_len = 2;
          pad_char = ' ';
          break;
      }

      if (prefix_char != NUL) {
        *--s = prefix_char;
        s_len++;
      }
      if (adjust_width && adjust == RIGHT && min_width > s_len) {
        if (pad_char == '0' && prefix_char != NUL) {
          appendchar(&result, &outpos, &size, *s);
          s++;
          s_len--;
          min_width--;
        }
        for (int i = 0; i < min_width - s_len; i++) {
          appendchar(&result, &outpos, &size, pad_char);
        }
      }
      
      appendsimplestring(&result, &outpos, &size, s, s_len);

      if (adjust_width && adjust == LEFT && min_width > s_len) {
        for (int i = 0; i < min_width - s_len; i++) {
          appendchar(&result, &outpos, &size, pad_char);
        }
      }
    }
skip_output:
    fmt++;
  }
  
  result[outpos] = NUL;
  *outbuf = result;
  return outpos;
}


int vspprintf(char** pbuf, size_t , const char* format, ...) {
  int len;
  va_list ap;
  va_start(ap, format);
  len = xbuf_format_converter(pbuf, format, ap);
  va_end(ap);
  return len;
}


int vspprintf_ap(char** pbuf, size_t , const char* format, va_list ap) {
  int len;
  len = xbuf_format_converter(pbuf, format, ap);
  return len;
}

int spprintf(char **pbuf, size_t max_len, const char *format, ...)
{
  int cc;
  va_list ap;

  va_start(ap, format);
  cc = vspprintf(pbuf, max_len, format, ap);
  va_end(ap);
  return (cc);
}


}
