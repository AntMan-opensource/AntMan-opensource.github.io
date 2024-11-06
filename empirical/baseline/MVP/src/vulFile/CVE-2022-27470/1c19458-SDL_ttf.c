











































static hb_direction_t g_hb_direction = HB_DIRECTION_LTR;
static hb_script_t    g_hb_script = HB_SCRIPT_UNKNOWN;



int TTF_SetDirection(int direction) 
{

    g_hb_direction = direction;
    return 0;

    (void) direction;
    return -1;

}

int TTF_SetScript(int script) 
{

    g_hb_script = script;
    return 0;

    (void) script;
    return -1;

}






























static SDL_INLINE int hasSSE2()
{
    static int val = -1;
    if (val != -1) {
        return val;
    }
    val = SDL_HasSSE2();
    return val;
}



static SDL_INLINE int hasNEON()
{
    static int val = -1;
    if (val != -1) {
        return val;
    }
    val = SDL_HasNEON();
    return val;
}






























typedef struct {
    unsigned char *buffer; 
    int            left;
    int            top;
    int            width;
    int            rows;
    int            pitch;
    int            is_color;
} TTF_Image;


typedef struct cached_glyph {
    int stored;
    FT_UInt index;
    TTF_Image bitmap;
    TTF_Image pixmap;
    int sz_left;
    int sz_top;
    int sz_width;
    int sz_rows;
    int advance;
    union {
        
        struct {
            int lsb_minus_rsb;
            int translation;
        } subpixel;
        
        struct {
            int rsb_delta;
            int lsb_delta;
        } kerning_smart;
    };
} c_glyph;


typedef struct PosBuf {
    FT_UInt index;
    int x;
    int y;
} PosBuf_t;


struct _TTF_Font {
    
    FT_Face face;

    
    int height;
    int ascent;
    int descent;
    int lineskip;

    
    int style;
    int outline_val;

    
    int allow_kerning;
    int use_kerning;

    
    int glyph_overhang;

    
    int line_thickness;
    int underline_top_row;
    int strikethrough_top_row;

    
    c_glyph cache[256];
    FT_UInt cache_index[128];

    
    SDL_RWops *src;
    int freesrc;
    FT_Open_Args args;

    
    PosBuf_t *pos_buf;
    Uint32 pos_len;
    Uint32 pos_max;

    
    int ft_load_target;
    int render_subpixel;

    hb_font_t *hb_font;
    hb_script_t hb_script;
    hb_direction_t hb_direction;

    int render_sdf;
};











static FT_Library library = NULL;
static int TTF_initialized = 0;
static SDL_bool TTF_byteswapped = SDL_FALSE;











typedef enum {
    RENDER_SOLID = 0, RENDER_SHADED, RENDER_BLENDED } render_mode_t;



typedef enum {
    STR_UTF8 = 0, STR_TEXT, STR_UNICODE } str_type_t;



static int TTF_initFontMetrics(TTF_Font *font);

static int TTF_Size_Internal(TTF_Font *font, const char *text, str_type_t str_type, int *w, int *h, int *xstart, int *ystart, int measure_width, int *extent, int *count);




static SDL_Surface* TTF_Render_Internal(TTF_Font *font, const char *text, str_type_t str_type, SDL_Color fg, SDL_Color bg, render_mode_t render_mode);

static SDL_Surface* TTF_Render_Wrapped_Internal(TTF_Font *font, const char *text, str_type_t str_type, SDL_Color fg, SDL_Color bg, Uint32 wrapLength, render_mode_t render_mode);

static SDL_INLINE int Find_GlyphByIndex(TTF_Font *font, FT_UInt idx, int want_bitmap, int want_pixmap, int want_color, int want_subpixel, int translation, c_glyph **out_glyph, TTF_Image **out_image);


static void Flush_Cache(TTF_Font *font);





























static SDL_INLINE void BG_Blended_Color(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip, Uint8 fg_alpha)
{
    const Uint32 *src   = (Uint32 *)image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width;
    Uint32       height = image->rows;

    if (fg_alpha == 0) { 
        while (height--) {
            
            DUFFS_LOOP4( *dst++ = *src++;
            , width);
            
            src = (const Uint32 *)((const Uint8 *)src + srcskip);
            dst = (Uint32 *)((Uint8 *)dst + dstskip);
        }
    } else {
        Uint32 alpha;
        Uint32 tmp;

        while (height--) {
            
            DUFFS_LOOP4( tmp = *src++;
                    alpha = tmp >> 24;
                    tmp &= ~0xFF000000;
                    alpha = fg_alpha * alpha;
                    alpha =  DIVIDE_BY_255(alpha) << 24;
                    *dst++ = tmp | alpha , width);
            
            src = (const Uint32 *)((const Uint8 *)src + srcskip);
            dst = (Uint32 *)((Uint8 *)dst + dstskip);
        }
    }
}




static SDL_INLINE void BG_Blended_Opaque_SDF(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint8 *src    = image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width;
    Uint32       height = image->rows;

    Uint32 s;
    Uint32 d;

    while (height--) {
        
        DUFFS_LOOP4( d = *dst;
            s = *src++ << 24;
            if (s > d) {
                *dst = s;
            }
            dst++;
        , width);
        
        src += srcskip;
        dst  = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}


static SDL_INLINE void BG_Blended_SDF(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip, Uint8 fg_alpha)
{
    const Uint8 *src    = image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width;
    Uint32       height = image->rows;

    Uint32 s;
    Uint32 d;

    Uint32 tmp;
    while (height--) {
        
        DUFFS_LOOP4( d = *dst;
            tmp = fg_alpha * (*src++);
            s = DIVIDE_BY_255(tmp) << 24;
            if (s > d) {
                *dst = s;
            }
            dst++;
        , width);
        
        src += srcskip;
        dst  = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}




static SDL_INLINE void BG_Blended_Opaque(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint8 *src    = image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width;
    Uint32       height = image->rows;

    while (height--) {
        
        DUFFS_LOOP4( *dst++ |= *src++ << 24;
        , width);
        
        src += srcskip;
        dst  = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}


static SDL_INLINE void BG_Blended(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip, Uint8 fg_alpha)
{
    const Uint8 *src    = image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width;
    Uint32       height = image->rows;

    Uint32 tmp;

    while (height--) {
        
        DUFFS_LOOP4( tmp     = fg_alpha * (*src++);
            *dst++ |= DIVIDE_BY_255(tmp) << 24;
        , width);
        
        src += srcskip;
        dst  = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}


static SDL_INLINE void BG_Blended_Opaque_32(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint8 *src    = image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width / 4;
    Uint32       height = image->rows;

    while (height--) {
        
        DUFFS_LOOP4( *dst++ |= *src++ << 24;
            *dst++ |= *src++ << 24;
            *dst++ |= *src++ << 24;
            *dst++ |= *src++ << 24;
        , width);
        
        src += srcskip;
        dst  = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}

static SDL_INLINE void BG_Blended_32(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip, Uint8 fg_alpha)
{
    const Uint8 *src    = image->buffer;
    Uint32      *dst    = destination;
    Uint32       width  = image->width / 4;
    Uint32       height = image->rows;

    Uint32 tmp0, tmp1, tmp2, tmp3;

    while (height--) {
        
        DUFFS_LOOP4( tmp0    = fg_alpha * (*src++);
            tmp1    = fg_alpha * (*src++);
            tmp2    = fg_alpha * (*src++);
            tmp3    = fg_alpha * (*src++);
            *dst++ |= DIVIDE_BY_255(tmp0) << 24;
            *dst++ |= DIVIDE_BY_255(tmp1) << 24;
            *dst++ |= DIVIDE_BY_255(tmp2) << 24;
            *dst++ |= DIVIDE_BY_255(tmp3) << 24;
        , width);
        
        src += srcskip;
        dst  = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}




static SDL_INLINE void BG_Blended_Opaque_SSE(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const __m128i *src    = (__m128i *)image->buffer;
    __m128i       *dst    = (__m128i *)destination;
    Uint32         width  = image->width / 16;
    Uint32         height = image->rows;

    __m128i s, s0, s1, s2, s3, d0, d1, d2, d3, r0, r1, r2, r3, L, H;
    const __m128i zero  = _mm_setzero_si128();

    while (height--) {
        
        DUFFS_LOOP4(  s  = _mm_loadu_si128(src);

            d0 = _mm_load_si128(dst);           
            d1 = _mm_load_si128(dst + 1);       
            d2 = _mm_load_si128(dst + 2);       
            d3 = _mm_load_si128(dst + 3);       

            L  = _mm_unpacklo_epi8(zero, s);
            H  = _mm_unpackhi_epi8(zero, s);

            s0 = _mm_unpacklo_epi8(zero, L);
            s1 = _mm_unpackhi_epi8(zero, L);
            s2 = _mm_unpacklo_epi8(zero, H);
            s3 = _mm_unpackhi_epi8(zero, H);
                                                
            r0 = _mm_or_si128(d0, s0);          
            r1 = _mm_or_si128(d1, s1);          
            r2 = _mm_or_si128(d2, s2);          
            r3 = _mm_or_si128(d3, s3);          

            _mm_store_si128(dst, r0);           
            _mm_store_si128(dst + 1, r1);       
            _mm_store_si128(dst + 2, r2);       
            _mm_store_si128(dst + 3, r3);       

            dst += 4;
            src += 1;
        , width);
        
        src = (const __m128i *)((const Uint8 *)src + srcskip);
        dst = (__m128i *)((Uint8 *)dst + dstskip);
    }
}

static SDL_INLINE void BG_Blended_SSE(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip, Uint8 fg_alpha)
{
    const __m128i *src    = (__m128i *)image->buffer;
    __m128i       *dst    = (__m128i *)destination;
    Uint32         width  = image->width / 16;
    Uint32         height = image->rows;

    const __m128i alpha = _mm_set1_epi16(fg_alpha);
    const __m128i one   = _mm_set1_epi16(1);
    const __m128i zero  = _mm_setzero_si128();
    __m128i s, s0, s1, s2, s3, d0, d1, d2, d3, r0, r1, r2, r3, L, H, Ls8, Hs8;

    while (height--) {
        
        DUFFS_LOOP4(  s  = _mm_loadu_si128(src);

            d0 = _mm_load_si128(dst);           
            d1 = _mm_load_si128(dst + 1);       
            d2 = _mm_load_si128(dst + 2);       
            d3 = _mm_load_si128(dst + 3);       

            L  = _mm_unpacklo_epi8(s, zero);    
            H  = _mm_unpackhi_epi8(s, zero);    

            
            

            L  = _mm_mullo_epi16(L, alpha);     
            H  = _mm_mullo_epi16(H, alpha);

            Ls8 = _mm_srli_epi16(L, 8);         
            Hs8 = _mm_srli_epi16(H, 8);
            L = _mm_add_epi16(L, one);          
            H = _mm_add_epi16(H, one);
            L = _mm_add_epi16(L, Ls8);          
            H = _mm_add_epi16(H, Hs8);
            L = _mm_srli_epi16(L, 8);           
            H = _mm_srli_epi16(H, 8);

            L = _mm_slli_epi16(L, 8);           
            H = _mm_slli_epi16(H, 8);           

            s0 = _mm_unpacklo_epi8(zero, L);
            s1 = _mm_unpackhi_epi8(zero, L);
            s2 = _mm_unpacklo_epi8(zero, H);
            s3 = _mm_unpackhi_epi8(zero, H);
                                                

            r0 = _mm_or_si128(d0, s0);          
            r1 = _mm_or_si128(d1, s1);          
            r2 = _mm_or_si128(d2, s2);          
            r3 = _mm_or_si128(d3, s3);          

            _mm_store_si128(dst, r0);           
            _mm_store_si128(dst + 1, r1);       
            _mm_store_si128(dst + 2, r2);       
            _mm_store_si128(dst + 3, r3);       

            dst += 4;
            src += 1;
        , width);
        
        src = (const __m128i *)((const Uint8 *)src + srcskip);
        dst = (__m128i *)((Uint8 *)dst + dstskip);
    }
}




static SDL_INLINE void BG_Blended_Opaque_NEON(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint32 *src    = (Uint32 *)image->buffer;
    Uint32       *dst    = destination;
    Uint32        width  = image->width / 16;
    Uint32        height = image->rows;

    uint32x4_t s, d0, d1, d2, d3, r0, r1, r2, r3;
    uint8x16x2_t sx, sx01, sx23;
    uint32x4_t zero = vmovq_n_u32(0);

    while (height--) {
        
        DUFFS_LOOP4(   s   = vld1q_u32(src);


            d0  = vld1q_u32(dst);               
            d1  = vld1q_u32(dst + 4);           
            d2  = vld1q_u32(dst + 8);           
            d3  = vld1q_u32(dst + 12);          

            sx   = vzipq_u8(zero, s);           
            sx01 = vzipq_u8(zero, sx.val[0]);   
            sx23 = vzipq_u8(zero, sx.val[1]);   
                                                
            r0  = vorrq_u32(d0, sx01.val[0]);   
            r1  = vorrq_u32(d1, sx01.val[1]);   
            r2  = vorrq_u32(d2, sx23.val[0]);   
            r3  = vorrq_u32(d3, sx23.val[1]);   

            vst1q_u32(dst, r0);                 
            vst1q_u32(dst + 4, r1);             
            vst1q_u32(dst + 8, r2);             
            vst1q_u32(dst + 12, r3);            

            dst += 16;
            src += 4;
        , width);
        
        src = (const Uint32 *)((const Uint8 *)src + srcskip);
        dst = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}


static SDL_INLINE void BG_Blended_NEON(const TTF_Image *image, Uint32 *destination, Sint32 srcskip, Uint32 dstskip, Uint8 fg_alpha)
{
    const Uint32 *src    = (Uint32 *)image->buffer;
    Uint32       *dst    = destination;
    Uint32        width  = image->width / 16;
    Uint32        height = image->rows;

    uint32x4_t s, d0, d1, d2, d3, r0, r1, r2, r3;
    uint16x8_t Ls8, Hs8;
    uint8x16x2_t sx, sx01, sx23;

    const uint16x8_t alpha = vmovq_n_u16(fg_alpha);
    const uint16x8_t one   = vmovq_n_u16(1);
    const uint32x4_t zero  = vmovq_n_u32(0);

    while (height--) {
        
        DUFFS_LOOP4(   s  = vld1q_u32(src);


            d0 = vld1q_u32(dst);                        
            d1 = vld1q_u32(dst + 4);                    
            d2 = vld1q_u32(dst + 8);                    
            d3 = vld1q_u32(dst + 12);                   

            sx = vzipq_u8(s, zero);                     
                                                        

            
            

            sx.val[0] = vmulq_u16(sx.val[0], alpha);    
            sx.val[1] = vmulq_u16(sx.val[1], alpha);

            Ls8 = vshrq_n_u16(sx.val[0], 8);            
            Hs8 = vshrq_n_u16(sx.val[1], 8);

            sx.val[0] = vaddq_u16(sx.val[0], one);      
            sx.val[1] = vaddq_u16(sx.val[1], one);

            sx.val[0] = vaddq_u16(sx.val[0], Ls8);      
            sx.val[1] = vaddq_u16(sx.val[1], Hs8);

            sx.val[0] = vshrq_n_u16(sx.val[0], 8);      
            sx.val[1] = vshrq_n_u16(sx.val[1], 8);

            sx.val[0] = vshlq_n_u16(sx.val[0], 8);      
            sx.val[1] = vshlq_n_u16(sx.val[1], 8);      

            sx01 = vzipq_u8(zero, sx.val[0]);           
            sx23 = vzipq_u8(zero, sx.val[1]);           
                                                        

            r0  = vorrq_u32(d0, sx01.val[0]);           
            r1  = vorrq_u32(d1, sx01.val[1]);           
            r2  = vorrq_u32(d2, sx23.val[0]);           
            r3  = vorrq_u32(d3, sx23.val[1]);           

            vst1q_u32(dst, r0);                         
            vst1q_u32(dst + 4, r1);                     
            vst1q_u32(dst + 8, r2);                     
            vst1q_u32(dst + 12, r3);                    

            dst += 16;
            src += 4;
        , width);
        
        src = (const Uint32 *)((const Uint8 *)src + srcskip);
        dst = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}


static SDL_INLINE void BG(const TTF_Image *image, Uint8 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint8 *src    = image->buffer;
    Uint8       *dst    = destination;
    Uint32       width  = image->width;
    Uint32       height = image->rows;

    while (height--) {
        
        DUFFS_LOOP4( *dst++ |= *src++;
        , width);
        
        src += srcskip;
        dst += dstskip;
    }
}


static SDL_INLINE void BG_64(const TTF_Image *image, Uint8 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint64 *src    = (Uint64 *)image->buffer;
    Uint64       *dst    = (Uint64 *)destination;
    Uint32        width  = image->width / 8;
    Uint32        height = image->rows;

    while (height--) {
        
        DUFFS_LOOP4( *dst++ |= *src++;
        , width);
        
        src = (const Uint64 *)((const Uint8 *)src + srcskip);
        dst = (Uint64 *)((Uint8 *)dst + dstskip);
    }
}

static SDL_INLINE void BG_32(const TTF_Image *image, Uint8 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint32 *src    = (Uint32 *)image->buffer;
    Uint32       *dst    = (Uint32 *)destination;
    Uint32        width  = image->width / 4;
    Uint32        height = image->rows;

    while (height--) {
        
        DUFFS_LOOP4( *dst++ |= *src++;
        , width);
        
        src = (const Uint32 *)((const Uint8 *)src + srcskip);
        dst = (Uint32 *)((Uint8 *)dst + dstskip);
    }
}



static SDL_INLINE void BG_SSE(const TTF_Image *image, Uint8 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const __m128i *src    = (__m128i *)image->buffer;
    __m128i       *dst    = (__m128i *)destination;
    Uint32         width  = image->width / 16;
    Uint32         height = image->rows;

    __m128i s, d, r;

    while (height--) {
        
        DUFFS_LOOP4( s = _mm_loadu_si128(src);
            d = _mm_load_si128(dst);    
            r = _mm_or_si128(d, s);     
            _mm_store_si128(dst, r);    
            src += 1;
            dst += 1;
        , width);
        
        src = (const __m128i *)((const Uint8 *)src + srcskip);
        dst = (__m128i *)((Uint8 *)dst + dstskip);
    }
}



static SDL_INLINE void BG_NEON(const TTF_Image *image, Uint8 *destination, Sint32 srcskip, Uint32 dstskip)
{
    const Uint8 *src    = image->buffer;
    Uint8       *dst    = destination;
    Uint32       width  = image->width / 16;
    Uint32       height = image->rows;

    uint8x16_t s, d, r;

    while (height--) {
        
        DUFFS_LOOP4( s = vld1q_u8(src);
            d = vld1q_u8(dst);  
            r = vorrq_u8(d, s); 
            vst1q_u8(dst, r);   
            src += 16;
            dst += 16;
        , width);
        
        src = (const Uint8 *)((const Uint8 *)src + srcskip);
        dst += dstskip;
    }
}



static void Draw_Line(TTF_Font *font, const SDL_Surface *textbuf, int row, int line_width, int line_thickness, Uint32 color, const render_mode_t render_mode)
{
    int tmp    = row + line_thickness - textbuf->h;
    Uint8 *dst = (Uint8 *)textbuf->pixels + row * textbuf->pitch;


    
    if (font->hb_direction == HB_DIRECTION_TTB || font->hb_direction == HB_DIRECTION_BTT) {
        return;
    }


    
    if (tmp > 0) {
        line_thickness -= tmp;
    }

    
    line_width = SDL_min(line_width, textbuf->w);

    if (render_mode == RENDER_BLENDED) {
        while (line_thickness--) {
            SDL_memset4(dst, color, line_width);
            dst += textbuf->pitch;
        }
    } else {
        while (line_thickness--) {
            SDL_memset(dst, color, line_width);
            dst += textbuf->pitch;
        }
    }
}

static void clip_glyph(int *_x, int *_y, TTF_Image *image, const SDL_Surface *textbuf)
{
    int above_w;
    int above_h;
    int x = *_x;
    int y = *_y;

    int srcbpp = 1;
    if (image->is_color) {
        
        srcbpp = 4;
    }

    
    if (x < 0) {
        int tmp = -x;
        x = 0;
        image->width  -= tmp;
        image->buffer += srcbpp * tmp;
    }
    
    above_w = x + image->width - textbuf->w;
    if (above_w > 0) {
        image->width -= above_w;
    }
    
    if (y < 0) {
        int tmp = -y;
        y = 0;
        image->rows   -= tmp;
        image->buffer += tmp * image->pitch;
    }
    
    above_h = y + image->rows - textbuf->h;
    if (above_h > 0) {
        image->rows -= above_h;
    }
    
    image->width = SDL_max(0, image->width);
    image->rows  = SDL_max(0, image->rows);

    
    if (image->width == 0) {
        image->rows = 0;
    }

    *_x = x;
    *_y = y;
}


static int Get_Alignement()
{

    if (hasNEON()) {
        return 16;
    }



    if (hasSSE2()) {
        return 16;
    }



    return 8;

    return 4;

    return 1;

}















































































































BUILD_RENDER_LINE(SSE_Shaded            , 0, 0, PIXMAP, 0     ,                       ,                , BG_SSE     )
BUILD_RENDER_LINE(SSE_Blended           , 1, 0,  COLOR, 0     ,                       , BG_Blended_SSE ,            )
BUILD_RENDER_LINE(SSE_Blended_Opaque    , 1, 1,  COLOR, 0     , BG_Blended_Opaque_SSE ,                ,            )
BUILD_RENDER_LINE(SSE_Solid             , 0, 0, BITMAP, 0     ,                       ,                , BG_SSE     )
BUILD_RENDER_LINE(SSE_Shaded_SP         , 0, 0, PIXMAP, SUBPIX,                       ,                , BG_SSE     )
BUILD_RENDER_LINE(SSE_Blended_SP        , 1, 0,  COLOR, SUBPIX,                       , BG_Blended_SSE ,            )
BUILD_RENDER_LINE(SSE_Blended_Opaque_SP , 1, 1,  COLOR, SUBPIX, BG_Blended_Opaque_SSE ,                ,            )



BUILD_RENDER_LINE(NEON_Shaded           , 0, 0, PIXMAP, 0     ,                       ,                , BG_NEON    )
BUILD_RENDER_LINE(NEON_Blended          , 1, 0,  COLOR, 0     ,                       , BG_Blended_NEON,            )
BUILD_RENDER_LINE(NEON_Blended_Opaque   , 1, 1,  COLOR, 0     , BG_Blended_Opaque_NEON,                ,            )
BUILD_RENDER_LINE(NEON_Solid            , 0, 0, BITMAP, 0     ,                       ,                , BG_NEON    )
BUILD_RENDER_LINE(NEON_Shaded_SP        , 0, 0, PIXMAP, SUBPIX,                       ,                , BG_NEON    )
BUILD_RENDER_LINE(NEON_Blended_SP       , 1, 0,  COLOR, SUBPIX,                       , BG_Blended_NEON,            )
BUILD_RENDER_LINE(NEON_Blended_Opaque_SP, 1, 1,  COLOR, SUBPIX, BG_Blended_Opaque_NEON,                ,            )



BUILD_RENDER_LINE(64_Shaded             , 0, 0, PIXMAP, 0     ,                       ,                , BG_64      )
BUILD_RENDER_LINE(64_Blended            , 1, 0,  COLOR, 0     ,                       , BG_Blended_32  ,            )
BUILD_RENDER_LINE(64_Blended_Opaque     , 1, 1,  COLOR, 0     , BG_Blended_Opaque_32  ,                ,            )
BUILD_RENDER_LINE(64_Solid              , 0, 0, BITMAP, 0     ,                       ,                , BG_64      )
BUILD_RENDER_LINE(64_Shaded_SP          , 0, 0, PIXMAP, SUBPIX,                       ,                , BG_64      )
BUILD_RENDER_LINE(64_Blended_SP         , 1, 0,  COLOR, SUBPIX,                       , BG_Blended_32  ,            )
BUILD_RENDER_LINE(64_Blended_Opaque_SP  , 1, 1,  COLOR, SUBPIX, BG_Blended_Opaque_32  ,                ,            )

BUILD_RENDER_LINE(32_Shaded             , 0, 0, PIXMAP, 0     ,                       ,                , BG_32      )
BUILD_RENDER_LINE(32_Blended            , 1, 0,  COLOR, 0     ,                       , BG_Blended_32  ,            )
BUILD_RENDER_LINE(32_Blended_Opaque     , 1, 1,  COLOR, 0     , BG_Blended_Opaque_32  ,                ,            )
BUILD_RENDER_LINE(32_Solid              , 0, 0, BITMAP, 0     ,                       ,                , BG_32      )
BUILD_RENDER_LINE(32_Shaded_SP          , 0, 0, PIXMAP, SUBPIX,                       ,                , BG_32      )
BUILD_RENDER_LINE(32_Blended_SP         , 1, 0,  COLOR, SUBPIX,                       , BG_Blended_32  ,            )
BUILD_RENDER_LINE(32_Blended_Opaque_SP  , 1, 1,  COLOR, SUBPIX, BG_Blended_Opaque_32  ,                ,            )

BUILD_RENDER_LINE(8_Shaded              , 0, 0, PIXMAP, 0     ,                       ,                , BG         )
BUILD_RENDER_LINE(8_Blended             , 1, 0,  COLOR, 0     ,                       , BG_Blended     ,            )
BUILD_RENDER_LINE(8_Blended_Opaque      , 1, 1,  COLOR, 0     , BG_Blended_Opaque     ,                ,            )
BUILD_RENDER_LINE(8_Solid               , 0, 0, BITMAP, 0     ,                       ,                , BG         )
BUILD_RENDER_LINE(8_Shaded_SP           , 0, 0, PIXMAP, SUBPIX,                       ,                , BG         )
BUILD_RENDER_LINE(8_Blended_SP          , 1, 0,  COLOR, SUBPIX,                       , BG_Blended     ,            )
BUILD_RENDER_LINE(8_Blended_Opaque_SP   , 1, 1,  COLOR, SUBPIX, BG_Blended_Opaque     ,                ,            )




static int (*Render_Line_SDF_Shaded)(TTF_Font *font, SDL_Surface *textbuf, int xstart, int ystart, Uint8 fg_alpha) = NULL;
BUILD_RENDER_LINE(SDF_Blended           , 1, 0,  COLOR, 0     ,                       , BG_Blended_SDF ,            )
BUILD_RENDER_LINE(SDF_Blended_Opaque    , 1, 1,  COLOR, 0     , BG_Blended_Opaque_SDF ,                ,            )
static int (*Render_Line_SDF_Solid)(TTF_Font *font, SDL_Surface *textbuf, int xstart, int ystart, Uint8 fg_alpha) = NULL;
static int (*Render_Line_SDF_Shaded_SP)(TTF_Font *font, SDL_Surface *textbuf, int xstart, int ystart, Uint8 fg_alpha) = NULL;
BUILD_RENDER_LINE(SDF_Blended_SP        , 1, 0,  COLOR, SUBPIX,                       , BG_Blended_SDF ,            )
BUILD_RENDER_LINE(SDF_Blended_Opaque_SP , 1, 1,  COLOR, SUBPIX, BG_Blended_Opaque_SDF ,                ,            )






static SDL_INLINE int Render_Line(const render_mode_t render_mode, int subpixel, TTF_Font *font, SDL_Surface *textbuf, int xstart, int ystart, Uint8 fg_alpha)
{
    

    
    

    int is_opaque = (fg_alpha == SDL_ALPHA_OPAQUE);


























    if (font->render_sdf && render_mode == RENDER_BLENDED) {
        Call_Specific_Render_Line(SDF)
    }



    if (hasNEON()) {
        Call_Specific_Render_Line(NEON)
    }


    if (hasSSE2()) {
        Call_Specific_Render_Line(SSE)
    }


    Call_Specific_Render_Line(64)

    Call_Specific_Render_Line(32)

    Call_Specific_Render_Line(8)

}

static SDL_Surface* Create_Surface_Solid(int width, int height, SDL_Color fg, Uint32 *color)
{
    const int alignment = Get_Alignement() - 1;
    SDL_Surface *textbuf;
    Sint64 size;

    
    void *pixels, *ptr;
    
    Sint64 pitch = width + alignment;
    pitch += alignment;
    pitch &= ~alignment;
    size = height * pitch + sizeof (void *) + alignment;
    if (size < 0 || size > SDL_MAX_SINT32) {
        
        return NULL;
    }

    ptr = SDL_malloc((size_t)size);
    if (ptr == NULL) {
        return NULL;
    }

    
    pixels = (void *)(((uintptr_t)ptr + sizeof(void *) + alignment) & ~alignment);
    ((void **)pixels)[-1] = ptr;

    textbuf = SDL_CreateRGBSurfaceWithFormatFrom(pixels, width, height, 0, pitch, SDL_PIXELFORMAT_INDEX8);
    if (textbuf == NULL) {
        SDL_free(ptr);
        return NULL;
    }

    
    textbuf->flags &= ~SDL_PREALLOC;
    textbuf->flags |= SDL_SIMD_ALIGNED;

    
    SDL_memset(pixels, 0, height * pitch);

    
    *color = 1;

    
    {
        SDL_Palette *palette = textbuf->format->palette;
        palette->colors[0].r = 255 - fg.r;
        palette->colors[0].g = 255 - fg.g;
        palette->colors[0].b = 255 - fg.b;
        palette->colors[1].r = fg.r;
        palette->colors[1].g = fg.g;
        palette->colors[1].b = fg.b;
        palette->colors[1].a = fg.a;
    }

    SDL_SetColorKey(textbuf, SDL_TRUE, 0);

    return textbuf;
}

static SDL_Surface* Create_Surface_Shaded(int width, int height, SDL_Color fg, SDL_Color bg, Uint32 *color)
{
    const int alignment = Get_Alignement() - 1;
    SDL_Surface *textbuf;
    Sint64 size;
    Uint8 bg_alpha = bg.a;

    
    void *pixels, *ptr;
    
    Sint64 pitch = width + alignment;
    pitch += alignment;
    pitch &= ~alignment;
    size = height * pitch + sizeof (void *) + alignment;
    if (size < 0 || size > SDL_MAX_SINT32) {
        
        return NULL;
    }

    ptr = SDL_malloc((size_t)size);
    if (ptr == NULL) {
        return NULL;
    }

    
    pixels = (void *)(((uintptr_t)ptr + sizeof(void *) + alignment) & ~alignment);
    ((void **)pixels)[-1] = ptr;

    textbuf = SDL_CreateRGBSurfaceWithFormatFrom(pixels, width, height, 0, pitch, SDL_PIXELFORMAT_INDEX8);
    if (textbuf == NULL) {
        SDL_free(ptr);
        return NULL;
    }

    
    textbuf->flags &= ~SDL_PREALLOC;
    textbuf->flags |= SDL_SIMD_ALIGNED;

    
    SDL_memset(pixels, 0, height * pitch);

    
    *color = NUM_GRAYS - 1;

    
    if (fg.a != SDL_ALPHA_OPAQUE || bg.a != SDL_ALPHA_OPAQUE) {
        SDL_SetSurfaceBlendMode(textbuf, SDL_BLENDMODE_BLEND);

        
        if (bg.a == SDL_ALPHA_OPAQUE) {
            bg.a = 0;
        }
    }

    
    {
        SDL_Palette *palette = textbuf->format->palette;
        int rdiff  = fg.r - bg.r;
        int gdiff  = fg.g - bg.g;
        int bdiff  = fg.b - bg.b;
        int adiff  = fg.a - bg.a;
        int sign_r = (rdiff >= 0) ? 1 : 255;
        int sign_g = (gdiff >= 0) ? 1 : 255;
        int sign_b = (bdiff >= 0) ? 1 : 255;
        int sign_a = (adiff >= 0) ? 1 : 255;
        int i;

        for (i = 0; i < NUM_GRAYS; ++i) {
            
            int tmp_r = i * rdiff;
            int tmp_g = i * gdiff;
            int tmp_b = i * bdiff;
            int tmp_a = i * adiff;
            palette->colors[i].r = (Uint8)(bg.r + DIVIDE_BY_255_SIGNED(tmp_r, sign_r));
            palette->colors[i].g = (Uint8)(bg.g + DIVIDE_BY_255_SIGNED(tmp_g, sign_g));
            palette->colors[i].b = (Uint8)(bg.b + DIVIDE_BY_255_SIGNED(tmp_b, sign_b));
            palette->colors[i].a = (Uint8)(bg.a + DIVIDE_BY_255_SIGNED(tmp_a, sign_a));
        }

        
        palette->colors[0].a = bg_alpha;
    }

    return textbuf;
}

static SDL_Surface *Create_Surface_Blended(int width, int height, SDL_Color fg, Uint32 *color)
{
    const int alignment = Get_Alignement() - 1;
    SDL_Surface *textbuf = NULL;
    Uint32 bgcolor;

    
    bgcolor = (fg.r << 16) | (fg.g << 8) | fg.b;

    
    *color = bgcolor | (fg.a << 24);

    
    if (width != 0) {
        
        Sint64 size;
        void *pixels, *ptr;
        
        Sint64 pitch = (width + alignment) * 4;
        pitch += alignment;
        pitch &= ~alignment;
        size = height * pitch + sizeof (void *) + alignment;
        if (size < 0 || size > SDL_MAX_SINT32) {
            
            return NULL;
        }

        ptr = SDL_malloc((size_t)size);
        if (ptr == NULL) {
            return NULL;
        }

        
        pixels = (void *)(((uintptr_t)ptr + sizeof(void *) + alignment) & ~alignment);
        ((void **)pixels)[-1] = ptr;

        textbuf = SDL_CreateRGBSurfaceWithFormatFrom(pixels, width, height, 0, pitch, SDL_PIXELFORMAT_ARGB8888);
        if (textbuf == NULL) {
            SDL_free(ptr);
            return NULL;
        }

        
        textbuf->flags &= ~SDL_PREALLOC;
        textbuf->flags |= SDL_SIMD_ALIGNED;

        
        SDL_memset4(pixels, bgcolor, (height * pitch) / 4);

        
        if (fg.a != SDL_ALPHA_OPAQUE) {
            SDL_SetSurfaceBlendMode(textbuf, SDL_BLENDMODE_BLEND);
        }
    }

    return textbuf;
}


const SDL_version* TTF_Linked_Version(void)
{
    static SDL_version linked_version;
    SDL_TTF_VERSION(&linked_version);
    return &linked_version;
}


void TTF_ByteSwappedUNICODE(SDL_bool swapped)
{
    TTF_byteswapped = swapped;
}


static void TTF_SetFTError(const char *msg, FT_Error error)
{




    const struct {
      int          err_code;
      const char  *err_msg;
    } ft_errors[] =   unsigned int i;


    const char *err_msg = NULL;

    for (i = 0; i < sizeof (ft_errors) / sizeof (ft_errors[0]); ++i) {
        if (error == ft_errors[i].err_code) {
            err_msg = ft_errors[i].err_msg;
            break;
        }
    }
    if (!err_msg) {
        err_msg = "unknown FreeType error";
    }
    TTF_SetError("%s: %s", msg, err_msg);
}




int TTF_Init(void)
{
    int status = 0;



    int duffs = 0, sse2 = 0, neon = 0, compil_sse2 = 0, compil_neon = 0;

    duffs = 1;


    sse2 = hasSSE2();
    compil_sse2 = 1;


    neon = hasNEON();
    compil_neon = 1;

    SDL_Log("SDL_ttf: hasSSE2=%d hasNEON=%d alignment=%d duffs_loop=%d compil_sse2=%d compil_neon=%d", sse2, neon, Get_Alignement(), duffs, compil_sse2, compil_neon);

    SDL_Log("Sizeof TTF_Image: %d c_glyph: %d TTF_Font: %d", sizeof (TTF_Image), sizeof (c_glyph), sizeof (TTF_Font));


    if (!TTF_initialized) {
        FT_Error error = FT_Init_FreeType(&library);
        if (error) {
            TTF_SetFTError("Couldn't init FreeType engine", error);
            status = -1;
        }
    }
    if (status == 0) {
        ++TTF_initialized;


        
        int spread = 4;
        int overlaps = 0;
        FT_Property_Set( library, "bsdf", "spread", &spread);
        FT_Property_Set( library, "sdf", "spread", &spread);
        FT_Property_Set( library, "sdf", "overlaps", &overlaps);


    }
    return status;
}

SDL_COMPILE_TIME_ASSERT(FT_Int, sizeof(int) == sizeof(FT_Int)); 
void TTF_GetFreeTypeVersion(int *major, int *minor, int *patch)
{
    FT_Library_Version(library, major, minor, patch);
}

void TTF_GetHarfBuzzVersion(int *major, int *minor, int *patch)
{
    unsigned int hb_major = 0;
    unsigned int hb_minor = 0;
    unsigned int hb_micro = 0;


    hb_version(&hb_major, &hb_minor, &hb_micro);

    if (major) {
        *major = (int)hb_major;
    }
    if (minor) {
        *minor = (int)hb_minor;
    }
    if (patch) {
        *patch = (int)hb_micro;
    }
}

static unsigned long RWread( FT_Stream stream, unsigned long offset, unsigned char *buffer, unsigned long count )




{
    SDL_RWops *src;

    src = (SDL_RWops *)stream->descriptor.pointer;
    SDL_RWseek(src, (int)offset, RW_SEEK_SET);
    if (count == 0) {
        return 0;
    }
    return (unsigned long)SDL_RWread(src, buffer, 1, (int)count);
}

TTF_Font* TTF_OpenFontIndexDPIRW(SDL_RWops *src, int freesrc, int ptsize, long index, unsigned int hdpi, unsigned int vdpi)
{
    TTF_Font *font;
    FT_Error error;
    FT_Face face;
    FT_Stream stream;
    FT_CharMap found;
    Sint64 position;
    int i;

    if (!TTF_initialized) {
        TTF_SetError("Library not initialized");
        if (src && freesrc) {
            SDL_RWclose(src);
        }
        return NULL;
    }

    if (!src) {
        TTF_SetError("Passed a NULL font source");
        return NULL;
    }

    
    position = SDL_RWtell(src);
    if (position < 0) {
        TTF_SetError("Can't seek in stream");
        if (freesrc) {
            SDL_RWclose(src);
        }
        return NULL;
    }

    font = (TTF_Font *)SDL_malloc(sizeof (*font));
    if (font == NULL) {
        TTF_SetError("Out of memory");
        if (freesrc) {
            SDL_RWclose(src);
        }
        return NULL;
    }
    SDL_memset(font, 0, sizeof (*font));

    font->src = src;
    font->freesrc = freesrc;

    stream = (FT_Stream)SDL_malloc(sizeof (*stream));
    if (stream == NULL) {
        TTF_SetError("Out of memory");
        TTF_CloseFont(font);
        return NULL;
    }
    SDL_memset(stream, 0, sizeof (*stream));

    stream->read = RWread;
    stream->descriptor.pointer = src;
    stream->pos = (unsigned long)position;
    stream->size = (unsigned long)(SDL_RWsize(src) - position);

    font->args.flags = FT_OPEN_STREAM;
    font->args.stream = stream;

    error = FT_Open_Face(library, &font->args, index, &font->face);
    if (error || font->face == NULL) {
        TTF_SetFTError("Couldn't load font file", error);
        TTF_CloseFont(font);
        return NULL;
    }
    face = font->face;

    
    found = 0;

    for (i = 0; i < face->num_charmaps; i++) {
        FT_CharMap charmap = face->charmaps[i];
        SDL_Log("Found charmap: platform id %d, encoding id %d", charmap->platform_id, charmap->encoding_id);
    }

    if (!found) {
        for (i = 0; i < face->num_charmaps; i++) {
            FT_CharMap charmap = face->charmaps[i];
            if (charmap->platform_id == 3 && charmap->encoding_id == 10) { 
                found = charmap;
                break;
            }
        }
    }
    if (!found) {
        for (i = 0; i < face->num_charmaps; i++) {
            FT_CharMap charmap = face->charmaps[i];
            if ((charmap->platform_id == 3 && charmap->encoding_id == 1) 
             || (charmap->platform_id == 3 && charmap->encoding_id == 0) 
             || (charmap->platform_id == 2 && charmap->encoding_id == 1) 
             || (charmap->platform_id == 0)) { 
                found = charmap;
                break;
            }
        }
    }
    if (found) {
        
        FT_Set_Charmap(face, found);
    }

    
    font->style = TTF_STYLE_NORMAL;
    font->outline_val = 0;
    font->ft_load_target = FT_LOAD_TARGET_NORMAL;
    TTF_SetFontKerning(font, 1);

    font->pos_len = 0;
    font->pos_max = 16;
    font->pos_buf = (PosBuf_t *)SDL_malloc(font->pos_max * sizeof (font->pos_buf[0]));
    if (! font->pos_buf) {
        TTF_SetError("Out of memory");
        TTF_CloseFont(font);
        return NULL;
    }


    font->hb_font = hb_ft_font_create(face, NULL);
    if (font->hb_font == NULL) {
        TTF_SetError("Cannot create harfbuzz font");
        TTF_CloseFont(font);
        return NULL;
    }

    
    hb_ft_font_set_load_flags(font->hb_font, FT_LOAD_DEFAULT | font->ft_load_target);

    
    TTF_SetFontScript(font, g_hb_script);
    TTF_SetFontDirection(font, g_hb_direction);


    if (TTF_SetFontSizeDPI(font, ptsize, hdpi, vdpi) < 0) {
        TTF_SetFTError("Couldn't set font size", error);
        TTF_CloseFont(font);
        return NULL;
    }
    return font;
}

int TTF_SetFontSizeDPI(TTF_Font *font, int ptsize, unsigned int hdpi, unsigned int vdpi)
{
    FT_Face face = font->face;
    FT_Error error;

    
    if (FT_IS_SCALABLE(face)) {
        
        error = FT_Set_Char_Size(face, 0, ptsize * 64, hdpi, vdpi);
        if (error) {
            TTF_SetFTError("Couldn't set font size", error);
            return -1;
        }
    } else {
        
        if (face->num_fixed_sizes <= 0) {
            TTF_SetError("Couldn't select size : no num_fixed_sizes");
            return -1;
        }

        
        ptsize = SDL_max(ptsize, 0);
        ptsize = SDL_min(ptsize, face->num_fixed_sizes - 1);

        error = FT_Select_Size(face, ptsize);
        if (error) {
            TTF_SetFTError("Couldn't select size", error);
            return -1;
        }
    }

    if (TTF_initFontMetrics(font) < 0) {
        TTF_SetError("Cannot initialize metrics");
        return -1;
    }

    Flush_Cache(font);


    
    hb_ft_font_changed(font->hb_font);


    return 0;
}

int TTF_SetFontSize(TTF_Font *font, int ptsize)
{
    return TTF_SetFontSizeDPI(font, ptsize, 0, 0);
}


static int TTF_initFontMetrics(TTF_Font *font)
{
    FT_Face face = font->face;
    int underline_offset;

    
    if (FT_IS_SCALABLE(face)) {
        
        FT_Fixed scale       = face->size->metrics.y_scale;
        font->ascent         = FT_CEIL(FT_MulFix(face->ascender, scale));
        font->descent        = FT_CEIL(FT_MulFix(face->descender, scale));
        font->height         = FT_CEIL(FT_MulFix(face->ascender - face->descender, scale));
        font->lineskip       = FT_CEIL(FT_MulFix(face->height, scale));
        underline_offset     = FT_FLOOR(FT_MulFix(face->underline_position, scale));
        font->line_thickness = FT_FLOOR(FT_MulFix(face->underline_thickness, scale));
    } else {
        
        font->ascent         = FT_CEIL(face->size->metrics.ascender);
        font->descent        = FT_CEIL(face->size->metrics.descender);
        font->height         = FT_CEIL(face->size->metrics.height);
        font->lineskip       = FT_CEIL(face->size->metrics.height);
        
        underline_offset     = font->descent / 2;
        font->line_thickness = 1;
    }

    if (font->line_thickness < 1) {
        font->line_thickness = 1;
    }

    font->underline_top_row     = font->ascent - underline_offset - 1;
    font->strikethrough_top_row = font->height / 2;

    
    
    if (font->outline_val > 0) {
        int fo = font->outline_val;
        font->line_thickness        += 2 * fo;
        font->underline_top_row     -= fo;
        font->strikethrough_top_row -= fo;
    }

    
    font->underline_top_row     = SDL_max(0, font->underline_top_row);
    font->strikethrough_top_row = SDL_max(0, font->strikethrough_top_row);

    
    if (TTF_HANDLE_STYLE_UNDERLINE(font)) {
        int bottom_row = font->underline_top_row + font->line_thickness;
        font->height = SDL_max(font->height, bottom_row);
    }
    
    if (TTF_HANDLE_STYLE_STRIKETHROUGH(font)) {
        int bottom_row = font->strikethrough_top_row + font->line_thickness;
        font->height = SDL_max(font->height, bottom_row);
    }


    SDL_Log("Font metrics:");
    SDL_Log("ascent = %d, descent = %d", font->ascent, font->descent);
    SDL_Log("height = %d, lineskip = %d", font->height, font->lineskip);
    SDL_Log("underline_offset = %d, line_thickness = %d", underline_offset, font->line_thickness);
    SDL_Log("underline_top_row = %d, strikethrough_top_row = %d", font->underline_top_row, font->strikethrough_top_row);
    SDL_Log("scalable=%d fixed_sizes=%d", FT_IS_SCALABLE(face), FT_HAS_FIXED_SIZES(face));


    font->glyph_overhang = face->size->metrics.y_ppem / 10;

    return 0;
}

TTF_Font* TTF_OpenFontDPIRW( SDL_RWops *src, int freesrc, int ptsize, unsigned int hdpi, unsigned int vdpi )
{
    return TTF_OpenFontIndexDPIRW(src, freesrc, ptsize, 0, hdpi, vdpi);
}

TTF_Font* TTF_OpenFontIndexRW( SDL_RWops *src, int freesrc, int ptsize, long index )
{
    return TTF_OpenFontIndexDPIRW(src, freesrc, ptsize, index, 0, 0);
}

TTF_Font* TTF_OpenFontIndexDPI( const char *file, int ptsize, long index, unsigned int hdpi, unsigned int vdpi )
{
    SDL_RWops *rw = SDL_RWFromFile(file, "rb");
    if ( rw == NULL ) {
        return NULL;
    }
    return TTF_OpenFontIndexDPIRW(rw, 1, ptsize, index, hdpi, vdpi);
}

TTF_Font* TTF_OpenFontRW(SDL_RWops *src, int freesrc, int ptsize)
{
    return TTF_OpenFontIndexRW(src, freesrc, ptsize, 0);
}

TTF_Font* TTF_OpenFontDPI(const char *file, int ptsize, unsigned int hdpi, unsigned int vdpi)
{
    return TTF_OpenFontIndexDPI(file, ptsize, 0, hdpi, vdpi);
}

TTF_Font* TTF_OpenFontIndex(const char *file, int ptsize, long index)
{
    return TTF_OpenFontIndexDPI(file, ptsize, index, 0, 0);
}

TTF_Font* TTF_OpenFont(const char *file, int ptsize)
{
    return TTF_OpenFontIndex(file, ptsize, 0);
}

static void Flush_Glyph_Image(TTF_Image *image) {
    if (image->buffer) {
        SDL_free(image->buffer);
        image->buffer = NULL;
    }
}

static void Flush_Glyph(c_glyph *glyph)
{
    glyph->stored = 0;
    glyph->index = 0;
    Flush_Glyph_Image(&glyph->pixmap);
    Flush_Glyph_Image(&glyph->bitmap);
}

static void Flush_Cache(TTF_Font *font)
{
    int i;
    int size = sizeof (font->cache) / sizeof (font->cache[0]);

    for (i = 0; i < size; ++i) {
        if (font->cache[i].stored) {
            Flush_Glyph(&font->cache[i]);
        }
    }
}

static FT_Error Load_Glyph(TTF_Font *font, c_glyph *cached, int want, int translation)
{
    const int alignment = Get_Alignement() - 1;
    FT_GlyphSlot slot;
    FT_Error error;

    int ft_load = FT_LOAD_DEFAULT | font->ft_load_target;


    if (want & CACHED_COLOR) {
        ft_load |= FT_LOAD_COLOR;
    }


    error = FT_Load_Glyph(font->face, cached->index, ft_load);
    if (error) {
        goto ft_failure;
    }

    
    slot = font->face->glyph;

    
    if (cached->stored == 0) {
        cached->sz_left  = slot->bitmap_left;
        cached->sz_top   = slot->bitmap_top;
        cached->sz_rows  = slot->bitmap.rows;
        cached->sz_width = slot->bitmap.width;

        
        if (cached->sz_left == 0 && cached->sz_top == 0 && cached->sz_rows == 0 && cached->sz_width == 0) {
            FT_Glyph_Metrics *metrics = &slot->metrics;
            if (metrics) {
                int minx = FT_FLOOR(metrics->horiBearingX);
                int maxx = FT_CEIL(metrics->horiBearingX + metrics->width);
                int maxy = FT_FLOOR(metrics->horiBearingY);
                int miny = maxy - FT_CEIL(metrics->height);

                cached->sz_left  = minx;
                cached->sz_top   = maxy;
                cached->sz_rows  = maxy - miny;
                cached->sz_width = maxx - minx;
            }
        }

        
        cached->advance  = (int)slot->metrics.horiAdvance; 

        if (font->render_subpixel == 0) {
            
            cached->kerning_smart.rsb_delta = (int)slot->rsb_delta; 
            cached->kerning_smart.lsb_delta = (int)slot->lsb_delta; 
        } else {
            
            cached->subpixel.lsb_minus_rsb  = (int)(slot->lsb_delta - slot->rsb_delta); 
            cached->subpixel.translation    = 0; 
        }


        SDL_Log("Index=%d sz_left=%d sz_top=%d sz_width=%d sz_rows=%d advance=%d is_outline=%d is_bitmap=%d", cached->index, cached->sz_left, cached->sz_top, cached->sz_width, cached->sz_rows, cached->advance, slot->format == FT_GLYPH_FORMAT_OUTLINE, slot->format == FT_GLYPH_FORMAT_BITMAP);



        
        if (TTF_HANDLE_STYLE_BOLD(font)) {
            cached->sz_width += font->glyph_overhang;
            cached->advance  += F26Dot6(font->glyph_overhang);
        }

        
        if (TTF_HANDLE_STYLE_ITALIC(font) && slot->format == FT_GLYPH_FORMAT_OUTLINE) {
            cached->sz_width += (GLYPH_ITALICS * font->height) >> 16;
        }

        
        if (font->render_subpixel) {
            cached->sz_width += 1;
        }

        
        if (font->render_sdf) {
            
            cached->sz_width += 2 * 8;
            cached->sz_rows  += 2 * 8;
        }


        cached->stored |= CACHED_METRICS;
    }

    if (((want & CACHED_BITMAP) && !(cached->stored & CACHED_BITMAP)) || ((want & CACHED_PIXMAP) && !(cached->stored & CACHED_PIXMAP)) || ((want & CACHED_COLOR) && !(cached->stored & CACHED_COLOR)) || (want & CACHED_SUBPIX)


       ) {
        const int  mono  = (want & CACHED_BITMAP);
        TTF_Image *dst   = (mono ? &cached->bitmap : &cached->pixmap);
        FT_Glyph   glyph = NULL;
        FT_Bitmap *src;
        FT_Render_Mode ft_render_mode;

        if (mono) {
            ft_render_mode = FT_RENDER_MODE_MONO;
        } else {
            ft_render_mode = FT_RENDER_MODE_NORMAL;

            if ((want & CACHED_COLOR) && font->render_sdf) {
                ft_render_mode = FT_RENDER_MODE_SDF;
            }

        }

        
        if (want & CACHED_SUBPIX) {
            Flush_Glyph_Image(&cached->pixmap);
            FT_Outline_Translate(&slot->outline, translation, 0 );
            cached->subpixel.translation = translation;
        }

        
        if (TTF_HANDLE_STYLE_ITALIC(font) && slot->format == FT_GLYPH_FORMAT_OUTLINE) {
            FT_Matrix shear;
            shear.xx = 1 << 16;
            shear.xy = GLYPH_ITALICS;
            shear.yx = 0;
            shear.yy = 1 << 16;
            FT_Outline_Transform(&slot->outline, &shear);
        }

        
        if ((font->outline_val > 0 && slot->format == FT_GLYPH_FORMAT_OUTLINE)
            || slot->format == FT_GLYPH_FORMAT_BITMAP) {

            FT_BitmapGlyph bitmap_glyph;

            error = FT_Get_Glyph(slot, &glyph);
            if (error) {
                goto ft_failure;
            }

            if (font->outline_val > 0) {
                FT_Stroker stroker;
                error = FT_Stroker_New(library, &stroker);
                if (error) {
                    goto ft_failure;
                }
                FT_Stroker_Set(stroker, font->outline_val * 64, FT_STROKER_LINECAP_ROUND, FT_STROKER_LINEJOIN_ROUND, 0);
                FT_Glyph_Stroke(&glyph, stroker, 1 );
                FT_Stroker_Done(stroker);
            }

            
            error = FT_Glyph_To_Bitmap(&glyph, ft_render_mode, 0, 1);
            if (error) {
                FT_Done_Glyph(glyph);
                goto ft_failure;
            }

            
            bitmap_glyph = (FT_BitmapGlyph) glyph;
            src          = &bitmap_glyph->bitmap;

            
            dst->left   = bitmap_glyph->left;
            dst->top    = bitmap_glyph->top;
        } else {
            
            error = FT_Render_Glyph(slot, ft_render_mode);
            if (error) {
                goto ft_failure;
            }

            
            src         = &slot->bitmap;

            
            dst->left   = slot->bitmap_left;
            dst->top    = slot->bitmap_top;
        }

        
        dst->width  = src->width;
        dst->rows   = src->rows;
        dst->buffer = NULL;

        
        if (dst->width == 0) {
            dst->rows = 0;
        }

        
        if (TTF_HANDLE_STYLE_BOLD(font)) {
            dst->width += font->glyph_overhang;
        }

        
        dst->pitch = dst->width + alignment;

        if (src->pixel_mode == FT_PIXEL_MODE_BGRA) {
            dst->pitch += 3 * dst->width;
        }


        if (dst->rows != 0) {
            unsigned int i;

            
            dst->buffer = (unsigned char *)SDL_malloc(alignment + dst->pitch * dst->rows);

            if (!dst->buffer) {
                error = FT_Err_Out_Of_Memory;
                goto ft_failure;
            }

            
            SDL_memset(dst->buffer, 0, alignment + dst->pitch * dst->rows);

            
            dst->buffer += alignment;

            
            
            for (i = 0; i < (unsigned int)src->rows; i++) {
                unsigned char *srcp = src->buffer + i * src->pitch;
                unsigned char *dstp = dst->buffer + i * dst->pitch;
                unsigned int k, quotient, remainder;

                
                if (src->pixel_mode == FT_PIXEL_MODE_MONO) {
                    quotient  = src->width / 8;
                    remainder = src->width & 0x7;
                } else if (src->pixel_mode == FT_PIXEL_MODE_GRAY2) {
                    quotient  = src->width / 4;
                    remainder = src->width & 0x3;
                } else if (src->pixel_mode == FT_PIXEL_MODE_GRAY4) {
                    quotient  = src->width / 2;
                    remainder = src->width & 0x1;

                } else if (src->pixel_mode == FT_PIXEL_MODE_BGRA) {
                    quotient  = src->width;
                    remainder = 0;

                } else {
                    quotient  = src->width;
                    remainder = 0;
                }









































































                if (mono) {
                    if (src->pixel_mode == FT_PIXEL_MODE_MONO) {
                        while (quotient--) {
                            MONO_MONO(8);
                        }
                        MONO_MONO(remainder);
                    } else if (src->pixel_mode == FT_PIXEL_MODE_GRAY2) {
                        while (quotient--) {
                            MONO_GRAY2(4);
                        }
                        MONO_GRAY2(remainder);
                    } else if (src->pixel_mode == FT_PIXEL_MODE_GRAY4) {
                        while (quotient--) {
                            MONO_GRAY4(2);
                        }
                        MONO_GRAY4(remainder);
                    } else {
                        while (quotient--) {
                            unsigned char c = *srcp++;
                            *dstp++ = (c >= 0x80) ? 1 : 0;
                        }
                    }
                } else if (src->pixel_mode == FT_PIXEL_MODE_MONO) {
                    
                    while (quotient--) {
                        NORMAL_MONO(8);
                    }
                    NORMAL_MONO(remainder);
                } else if (src->pixel_mode == FT_PIXEL_MODE_GRAY2) {
                    while (quotient--) {
                        NORMAL_GRAY2(4);
                    }
                    NORMAL_GRAY2(remainder);
                } else if (src->pixel_mode == FT_PIXEL_MODE_GRAY4) {
                    while (quotient--) {
                        NORMAL_GRAY4(2);
                    }
                    NORMAL_GRAY4(remainder);

                } else if (src->pixel_mode == FT_PIXEL_MODE_BGRA) {
                    SDL_memcpy(dstp, srcp, 4 * src->width);

                } else {

                    if (ft_render_mode != FT_RENDER_MODE_SDF) {
                        SDL_memcpy(dstp, srcp, src->width);
                    } else {
                        int x;
                        for (x = 0; x < src->width; x++) {
                            Uint8 s = srcp[x];
                            Uint8 d;
                            if (s < 128) {
                                d = 256 - (128 - s) * 2;
                            } else {
                                d = 255;
                                
                            }
                            dstp[x] = d;
                        }
                    }

                    SDL_memcpy(dstp, srcp, src->width);

                }
            }
        }




        
        if (TTF_HANDLE_STYLE_BOLD(font)) {
            int row;
            
            for (row = dst->rows - 1; row >= 0; --row) {
                Uint8 *pixmap = dst->buffer + row * dst->pitch;
                int col, offset;
                
                
                for (offset = 1; offset <= font->glyph_overhang; ++offset) {
                    for (col = dst->width - 1; col > 0; --col) {
                        if (mono) {
                            pixmap[col] |= pixmap[col-1];
                        } else {
                            int pixel = (pixmap[col] + pixmap[col-1]);
                            if (pixel > NUM_GRAYS - 1) {
                                pixel = NUM_GRAYS - 1;
                            }
                            pixmap[col] = (Uint8) pixel;
                        }
                    }
                }
            }
        }

        
        if (dst->buffer) {
            dst->buffer -= alignment;
        }


        if (src->pixel_mode == FT_PIXEL_MODE_BGRA) {
            dst->is_color = 1;
        } else {
            dst->is_color = 0;
        }

        dst->is_color = 0;


        
        if (mono) {
            cached->stored |= CACHED_BITMAP;
        } else {

            if (want & CACHED_COLOR) {
                cached->stored |= CACHED_COLOR;
                
                if (dst->is_color == 0) {
                    cached->stored |= CACHED_PIXMAP;
                }
            } else {
                cached->stored |= CACHED_PIXMAP;
                
                if (!FT_HAS_COLOR(font->face)) {
                    cached->stored |= CACHED_COLOR;
                }
            }

            cached->stored |= CACHED_COLOR | CACHED_PIXMAP;

        }

        
        if (glyph) {
            FT_Done_Glyph(glyph);
        }
    }

    
    return 0;

ft_failure:
    TTF_SetFTError("Couldn't find glyph", error);
    return -1;
}

static SDL_INLINE int Find_GlyphByIndex(TTF_Font *font, FT_UInt idx, int want_bitmap, int want_pixmap, int want_color, int want_subpixel, int translation, c_glyph **out_glyph, TTF_Image **out_image)

{
    
    c_glyph *glyph = &font->cache[idx & 0xff];

    if (out_glyph) {
        *out_glyph = glyph;
    }

    if (want_pixmap || want_color) {
        *out_image = &glyph->pixmap;
    }

    if (want_bitmap) {
        *out_image = &glyph->bitmap;
    }

    if (want_subpixel)
    {
        
        int retval;
        int want = CACHED_METRICS | want_bitmap | want_pixmap | want_color | want_subpixel;

        if (glyph->stored && glyph->index != idx) {
            Flush_Glyph(glyph);
        }

        if (glyph->subpixel.translation == translation) {
            want &= ~CACHED_SUBPIX;
        }

        if ((glyph->stored & want) == want) {
            return 0;
        }

        glyph->index = idx;
        retval = Load_Glyph(font, glyph, want, translation);
        if (retval == 0) {
            return 0;
        } else {
            return -1;
        }
    }
    else {
        int retval;
        const int want = CACHED_METRICS | want_bitmap | want_pixmap | want_color;

        
        if (want_pixmap) {
            if ((glyph->stored & CACHED_PIXMAP) && glyph->index == idx) {
                return 0;
            }
        } else if (want_bitmap) {
            if ((glyph->stored & CACHED_BITMAP) && glyph->index == idx) {
                return 0;
            }
        } else if (want_color) {
            if ((glyph->stored & CACHED_COLOR) && glyph->index == idx) {
                return 0;
            }
        } else {
            
            if (glyph->stored && glyph->index == idx) {
                return 0;
            }
        }

        
        if (want_color || want_pixmap) {
            if (glyph->stored & (CACHED_COLOR|CACHED_PIXMAP)) {
                Flush_Glyph(glyph);
            }
        }

        if (glyph->stored && glyph->index != idx) {
            Flush_Glyph(glyph);
        }

        glyph->index = idx;
        retval = Load_Glyph(font, glyph, want, 0);
        if (retval == 0) {
            return 0;
        } else {
            return -1;
        }
    }
}

static SDL_INLINE FT_UInt get_char_index(TTF_Font *font, Uint32 ch)
{
    Uint32 cache_index_size = sizeof (font->cache_index) / sizeof (font->cache_index[0]);

    if (ch < cache_index_size) {
        FT_UInt idx = font->cache_index[ch];
        if (idx) {
            return idx;
        }
        idx = FT_Get_Char_Index(font->face, ch);
        font->cache_index[ch] = idx;
        return idx;
    }

    return FT_Get_Char_Index(font->face, ch);
}


static SDL_INLINE int Find_GlyphMetrics(TTF_Font *font, Uint32 ch, c_glyph **out_glyph)
{
    FT_UInt idx = get_char_index(font, ch);
    return Find_GlyphByIndex(font, idx, 0, 0, 0, 0, 0, out_glyph, NULL);
}

void TTF_CloseFont(TTF_Font *font)
{
    if (font) {

        hb_font_destroy(font->hb_font);

        Flush_Cache(font);
        if (font->face) {
            FT_Done_Face(font->face);
        }
        if (font->args.stream) {
            SDL_free(font->args.stream);
        }
        if (font->freesrc) {
            SDL_RWclose(font->src);
        }
        if (font->pos_buf) {
            SDL_free(font->pos_buf);
        }
        SDL_free(font);
    }
}


static size_t LATIN1_to_UTF8_len(const char *text)
{
    size_t bytes = 1;
    while (*text) {
        Uint8 ch = *(const Uint8 *)text++;
        if (ch <= 0x7F) {
            bytes += 1;
        } else {
            bytes += 2;
        }
    }
    return bytes;
}


static size_t UCS2_to_UTF8_len(const Uint16 *text)
{
    size_t bytes = 1;
    while (*text) {
        Uint16 ch = *text++;
        if (ch <= 0x7F) {
            bytes += 1;
        } else if (ch <= 0x7FF) {
            bytes += 2;
        } else {
            bytes += 3;
        }
    }
    return bytes;
}


static void LATIN1_to_UTF8(const char *src, Uint8 *dst)
{
    while (*src) {
        Uint8 ch = *(const Uint8 *)src++;
        if (ch <= 0x7F) {
            *dst++ = ch;
        } else {
            *dst++ = 0xC0 | ((ch >> 6) & 0x1F);
            *dst++ = 0x80 | (ch & 0x3F);
        }
    }
    *dst = '\0';
}


static void UCS2_to_UTF8(const Uint16 *src, Uint8 *dst)
{
    SDL_bool swapped = TTF_byteswapped;

    while (*src) {
        Uint16 ch = *src++;
        if (ch == UNICODE_BOM_NATIVE) {
            swapped = SDL_FALSE;
            continue;
        }
        if (ch == UNICODE_BOM_SWAPPED) {
            swapped = SDL_TRUE;
            continue;
        }
        if (swapped) {
            ch = SDL_Swap16(ch);
        }
        if (ch <= 0x7F) {
            *dst++ = (Uint8) ch;
        } else if (ch <= 0x7FF) {
            *dst++ = 0xC0 | (Uint8) ((ch >> 6) & 0x1F);
            *dst++ = 0x80 | (Uint8) (ch & 0x3F);
        } else {
            *dst++ = 0xE0 | (Uint8) ((ch >> 12) & 0x0F);
            *dst++ = 0x80 | (Uint8) ((ch >> 6) & 0x3F);
            *dst++ = 0x80 | (Uint8) (ch & 0x3F);
        }
    }
    *dst = '\0';
}


static SDL_bool Char_to_UTF8(Uint32 ch, Uint8 *dst)
{
    if (ch <= 0x7F) {
        *dst++ = (Uint8) ch;
    } else if (ch <= 0x7FF) {
        *dst++ = 0xC0 | (Uint8) ((ch >> 6) & 0x1F);
        *dst++ = 0x80 | (Uint8) (ch & 0x3F);
    } else if (ch <= 0xFFFF) {
        *dst++ = 0xE0 | (Uint8) ((ch >> 12) & 0x0F);
        *dst++ = 0x80 | (Uint8) ((ch >> 6) & 0x3F);
        *dst++ = 0x80 | (Uint8) (ch & 0x3F);
    } else if (ch <= 0x1FFFFF) {
        *dst++ = 0xF0 | (Uint8) ((ch >> 18) & 0x07);
        *dst++ = 0x80 | (Uint8) ((ch >> 12) & 0x3F);
        *dst++ = 0x80 | (Uint8) ((ch >> 6) & 0x3F);
        *dst++ = 0x80 | (Uint8) (ch & 0x3F);
    } else if (ch <= 0x3FFFFFF) {
        *dst++ = 0xF8 | (Uint8) ((ch >> 24) & 0x03);
        *dst++ = 0x80 | (Uint8) ((ch >> 18) & 0x3F);
        *dst++ = 0x80 | (Uint8) ((ch >> 12) & 0x3F);
        *dst++ = 0x80 | (Uint8) ((ch >> 6) & 0x3F);
        *dst++ = 0x80 | (Uint8) (ch & 0x3F);
    } else if (ch < 0x7FFFFFFF) {
        *dst++ = 0xFC | (Uint8) ((ch >> 30) & 0x01);
        *dst++ = 0x80 | (Uint8) ((ch >> 24) & 0x3F);
        *dst++ = 0x80 | (Uint8) ((ch >> 18) & 0x3F);
        *dst++ = 0x80 | (Uint8) ((ch >> 12) & 0x3F);
        *dst++ = 0x80 | (Uint8) ((ch >> 6) & 0x3F);
        *dst++ = 0x80 | (Uint8) (ch & 0x3F);
    } else {
        TTF_SetError("Invalid character");
        return SDL_FALSE;
    }
    *dst = '\0';
    return SDL_TRUE;
}



static Uint32 UTF8_getch(const char *src, size_t srclen, int *inc)
{
    const Uint8 *p = (const Uint8 *)src;
    size_t left = 0;
    size_t save_srclen = srclen;
    SDL_bool overlong = SDL_FALSE;
    SDL_bool underflow = SDL_FALSE;
    Uint32 ch = UNKNOWN_UNICODE;

    if (srclen == 0) {
        return UNKNOWN_UNICODE;
    }
    if (p[0] >= 0xFC) {
        if ((p[0] & 0xFE) == 0xFC) {
            if (p[0] == 0xFC && (p[1] & 0xFC) == 0x80) {
                overlong = SDL_TRUE;
            }
            ch = (Uint32) (p[0] & 0x01);
            left = 5;
        }
    } else if (p[0] >= 0xF8) {
        if ((p[0] & 0xFC) == 0xF8) {
            if (p[0] == 0xF8 && (p[1] & 0xF8) == 0x80) {
                overlong = SDL_TRUE;
            }
            ch = (Uint32) (p[0] & 0x03);
            left = 4;
        }
    } else if (p[0] >= 0xF0) {
        if ((p[0] & 0xF8) == 0xF0) {
            if (p[0] == 0xF0 && (p[1] & 0xF0) == 0x80) {
                overlong = SDL_TRUE;
            }
            ch = (Uint32) (p[0] & 0x07);
            left = 3;
        }
    } else if (p[0] >= 0xE0) {
        if ((p[0] & 0xF0) == 0xE0) {
            if (p[0] == 0xE0 && (p[1] & 0xE0) == 0x80) {
                overlong = SDL_TRUE;
            }
            ch = (Uint32) (p[0] & 0x0F);
            left = 2;
        }
    } else if (p[0] >= 0xC0) {
        if ((p[0] & 0xE0) == 0xC0) {
            if ((p[0] & 0xDE) == 0xC0) {
                overlong = SDL_TRUE;
            }
            ch = (Uint32) (p[0] & 0x1F);
            left = 1;
        }
    } else {
        if ((p[0] & 0x80) == 0x00) {
            ch = (Uint32) p[0];
        }
    }
    --srclen;
    while (left > 0 && srclen > 0) {
        ++p;
        if ((p[0] & 0xC0) != 0x80) {
            ch = UNKNOWN_UNICODE;
            break;
        }
        ch <<= 6;
        ch |= (p[0] & 0x3F);
        --srclen;
        --left;
    }
    if (left > 0) {
        underflow = SDL_TRUE;
    }
    
    

    (void) overlong;

    if (underflow || (ch >= 0xD800 && ch <= 0xDFFF) || (ch == 0xFFFE || ch == 0xFFFF) || ch > 0x10FFFF) {

        ch = UNKNOWN_UNICODE;
    }

    *inc = (int)(save_srclen - srclen);

    return ch;
}

int TTF_FontHeight(const TTF_Font *font)
{
    return font->height;
}

int TTF_FontAscent(const TTF_Font *font)
{
    return font->ascent + 2 * font->outline_val;
}

int TTF_FontDescent(const TTF_Font *font)
{
    return font->descent;
}

int TTF_FontLineSkip(const TTF_Font *font)
{
    return font->lineskip;
}

int TTF_GetFontKerning(const TTF_Font *font)
{
    return font->allow_kerning;
}

void TTF_SetFontKerning(TTF_Font *font, int allowed)
{
    font->allow_kerning = allowed;
    font->use_kerning   = allowed && FT_HAS_KERNING(font->face);
}

long TTF_FontFaces(const TTF_Font *font)
{
    return font->face->num_faces;
}

int TTF_FontFaceIsFixedWidth(const TTF_Font *font)
{
    return FT_IS_FIXED_WIDTH(font->face);
}

char* TTF_FontFaceFamilyName(const TTF_Font *font)
{
    return font->face->family_name;
}

char* TTF_FontFaceStyleName(const TTF_Font *font)
{
    return font->face->style_name;
}

int TTF_GlyphIsProvided(TTF_Font *font, Uint16 ch)
{
    return (int)get_char_index(font, ch);
}

int TTF_GlyphIsProvided32(TTF_Font *font, Uint32 ch)
{
    return (int)get_char_index(font, ch);
}

int TTF_GlyphMetrics(TTF_Font *font, Uint16 ch, int *minx, int *maxx, int *miny, int *maxy, int *advance)
{
    return TTF_GlyphMetrics32(font, ch, minx, maxx, miny, maxy, advance);
}

int TTF_GlyphMetrics32(TTF_Font *font, Uint32 ch, int *minx, int *maxx, int *miny, int *maxy, int *advance)
{
    c_glyph *glyph;

    TTF_CHECK_POINTER(font, -1);

    if (Find_GlyphMetrics(font, ch, &glyph) < 0) {
        return -1;
    }

    if (minx) {
        *minx = glyph->sz_left;
    }
    if (maxx) {
        *maxx = glyph->sz_left + glyph->sz_width;
        *maxx += 2 * font->outline_val;
    }
    if (miny) {
        *miny = glyph->sz_top - glyph->sz_rows;
    }
    if (maxy) {
        *maxy = glyph->sz_top;
        *maxy += 2 * font->outline_val;
    }
    if (advance) {
        *advance = FT_CEIL(glyph->advance);
    }
    return 0;
}

int TTF_SetFontDirection(TTF_Font *font, int direction) 
{

    font->hb_direction = direction;
    return 0;

    (void) direction;
    return -1;

}

int TTF_SetFontScript(TTF_Font *font, int script) 
{

    font->hb_script = script;
    return 0;

    (void) script;
    return -1;

}

static int TTF_Size_Internal(TTF_Font *font, const char *text, const str_type_t str_type, int *w, int *h, int *xstart, int *ystart, int measure_width, int *extent, int *count)


{
    int x = 0;
    int pos_x, pos_y;
    int minx = 0, maxx = 0;
    int miny = 0, maxy = 0;
    Uint8 *utf8_alloc = NULL;
    c_glyph *glyph;

    hb_buffer_t *hb_buffer = NULL;
    unsigned int g;
    unsigned int glyph_count;
    hb_glyph_info_t *hb_glyph_info;
    hb_glyph_position_t *hb_glyph_position;
    int y = 0;

    size_t textlen;
    int skip_first = 1;
    FT_UInt prev_index = 0;
    FT_Pos  prev_delta = 0;

    int prev_advance = 0;

    
    int char_count = 0;
    int current_width = 0;

    TTF_CHECK_INITIALIZED(-1);
    TTF_CHECK_POINTER(font, -1);
    TTF_CHECK_POINTER(text, -1);

    
    if (str_type == STR_TEXT) {
        utf8_alloc = SDL_stack_alloc(Uint8, LATIN1_to_UTF8_len(text));
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        LATIN1_to_UTF8(text, utf8_alloc);
        text = (const char *)utf8_alloc;
    } else if (str_type == STR_UNICODE) {
        const Uint16 *text16 = (const Uint16 *) text;
        utf8_alloc = SDL_stack_alloc(Uint8, UCS2_to_UTF8_len(text16));
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        UCS2_to_UTF8(text16, utf8_alloc);
        text = (const char *)utf8_alloc;
    }

    maxy = font->height;

    
    font->pos_len = 0;


    
    hb_buffer = hb_buffer_create();
    if (hb_buffer == NULL) {
       TTF_SetError("Cannot create harfbuzz buffer");
       goto failure;
    }

    
    hb_buffer_set_direction(hb_buffer, font->hb_direction);
    hb_buffer_set_script(hb_buffer, font->hb_script);

    
    hb_buffer_add_utf8(hb_buffer, text, -1, 0, -1);
    hb_shape(font->hb_font, hb_buffer, NULL, 0);

    
    hb_glyph_info = hb_buffer_get_glyph_infos(hb_buffer, &glyph_count);
    hb_glyph_position = hb_buffer_get_glyph_positions(hb_buffer, &glyph_count);

    
    for (g = 0; g < glyph_count; g++)
    {
        FT_UInt idx   = hb_glyph_info[g].codepoint;
        int x_advance = hb_glyph_position[g].x_advance;
        int y_advance = hb_glyph_position[g].y_advance;
        int x_offset  = hb_glyph_position[g].x_offset;
        int y_offset  = hb_glyph_position[g].y_offset;

    
    textlen = SDL_strlen(text);
    while (textlen > 0) {
        int inc = 0;
        Uint32 c = UTF8_getch(text, textlen, &inc);
        FT_UInt idx = get_char_index(font, c);
        text += inc;
        textlen -= inc;

        if (c == UNICODE_BOM_NATIVE || c == UNICODE_BOM_SWAPPED) {
            continue;
        }

        if (Find_GlyphByIndex(font, idx, 0, 0, 0, 0, 0, &glyph, NULL) < 0) {
            goto failure;
        }

        
        if (font->pos_len >= font->pos_max) {
            PosBuf_t *saved = font->pos_buf;
            font->pos_max *= 2;
            font->pos_buf = (PosBuf_t *)SDL_realloc(font->pos_buf, font->pos_max * sizeof (font->pos_buf[0]));
            if (font->pos_buf == NULL) {
                font->pos_max /= 2;
                font->pos_buf = saved;
                TTF_SetError("Out of memory");
                goto failure;
            }
        }


        
        pos_x  = x                     + x_offset;
        pos_y  = y + F26Dot6(font->ascent) - y_offset;
        x     += x_advance;
        y     += y_advance;

        
        x += prev_advance;
        prev_advance = glyph->advance;
        if (font->use_kerning) {
            if (prev_index && glyph->index) {
                FT_Vector delta;
                FT_Get_Kerning(font->face, prev_index, glyph->index, FT_KERNING_UNFITTED, &delta);
                x += delta.x;
            }
            prev_index = glyph->index;
        }
        
        if (font->render_subpixel) {
            x += prev_delta;
            
            prev_delta = glyph->subpixel.lsb_minus_rsb;
        } else {
            
            if (skip_first) {
                skip_first = 0;
            } else {
                if (prev_delta - glyph->kerning_smart.lsb_delta >  32 ) {
                    x -= 64;
                } else if (prev_delta - glyph->kerning_smart.lsb_delta < -31 ) {
                    x += 64;
                }
            }
            prev_delta = glyph->kerning_smart.rsb_delta;
            x = ((x + 32) & -64); 
        }

        
        pos_x = x;
        pos_y = F26Dot6(font->ascent);

        
        font->pos_buf[font->pos_len].x     = pos_x;
        font->pos_buf[font->pos_len].y     = pos_y;
        font->pos_buf[font->pos_len].index = idx;
        font->pos_len += 1;

        
        pos_x = FT_FLOOR(pos_x) + glyph->sz_left;
        pos_y = FT_FLOOR(pos_y) - glyph->sz_top;

        minx = SDL_min(minx, pos_x);
        maxx = SDL_max(maxx, pos_x + glyph->sz_width);
        miny = SDL_min(miny, pos_y);
        maxy = SDL_max(maxy, pos_y + glyph->sz_rows);

        
        if (measure_width) {
            int cw = SDL_max(maxx, FT_FLOOR(x + prev_advance)) - minx;
            cw += 2 * font->outline_val;
            if (cw >= measure_width) {
                break;
            }
            current_width = cw;
            char_count += 1;
        }
    }

    
    maxx = SDL_max(maxx, FT_FLOOR(x + prev_advance));

    
    if (xstart) {
        *xstart = (minx < 0)? -minx : 0;
        *xstart += font->outline_val;
        if (font->render_sdf) {
            *xstart += 8; 
        }
    }

    
    if (ystart) {
        *ystart = (miny < 0)? -miny : 0;
        *ystart += font->outline_val;
        if (font->render_sdf) {
            *ystart += 8; 
        }
    }

    
    if (w) {
        *w = (maxx - minx);
        if (*w != 0) {
            *w += 2 * font->outline_val;
        }
    }
    if (h) {
        *h = (maxy - miny);
        *h += 2 * font->outline_val;
    }

    
    if (measure_width) {
        if (extent) {
            *extent = current_width;
        }
        if (count) {
            *count = char_count;
        }
    }


    if (hb_buffer) {
        hb_buffer_destroy(hb_buffer);
    }

    if (utf8_alloc) {
        SDL_stack_free(utf8_alloc);
    }
    return 0;
failure:

    if (hb_buffer) {
        hb_buffer_destroy(hb_buffer);
    }

    if (utf8_alloc) {
        SDL_stack_free(utf8_alloc);
    }
    return -1;
}

int TTF_SizeText(TTF_Font *font, const char *text, int *w, int *h)
{
    return TTF_Size_Internal(font, text, STR_TEXT, w, h, NULL, NULL, NO_MEASUREMENT);
}

int TTF_SizeUTF8(TTF_Font *font, const char *text, int *w, int *h)
{
    return TTF_Size_Internal(font, text, STR_UTF8, w, h, NULL, NULL, NO_MEASUREMENT);
}

int TTF_SizeUNICODE(TTF_Font *font, const Uint16 *text, int *w, int *h)
{
    return TTF_Size_Internal(font, (const char *)text, STR_UNICODE, w, h, NULL, NULL, NO_MEASUREMENT);
}

int TTF_MeasureText(TTF_Font *font, const char *text, int width, int *extent, int *count)
{
    return TTF_Size_Internal(font, text, STR_TEXT, NULL, NULL, NULL, NULL, width, extent, count);
}

int TTF_MeasureUTF8(TTF_Font *font, const char *text, int width, int *extent, int *count)
{
    return TTF_Size_Internal(font, text, STR_UTF8, NULL, NULL, NULL, NULL, width, extent, count);
}

int TTF_MeasureUNICODE(TTF_Font *font, const Uint16 *text, int width, int *extent, int *count)
{
    return TTF_Size_Internal(font, (const char *)text, STR_UNICODE, NULL, NULL, NULL, NULL, width, extent, count);
}

static SDL_Surface* TTF_Render_Internal(TTF_Font *font, const char *text, const str_type_t str_type, SDL_Color fg, SDL_Color bg, const render_mode_t render_mode)
{
    Uint32 color;
    int xstart, ystart, width, height;
    SDL_Surface *textbuf = NULL;
    Uint8 *utf8_alloc = NULL;

    TTF_CHECK_INITIALIZED(NULL);
    TTF_CHECK_POINTER(font, NULL);
    TTF_CHECK_POINTER(text, NULL);

    
    if (str_type == STR_TEXT) {
        utf8_alloc = SDL_stack_alloc(Uint8, LATIN1_to_UTF8_len(text));
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        LATIN1_to_UTF8(text, utf8_alloc);
        text = (const char *)utf8_alloc;
    } else if (str_type == STR_UNICODE) {
        const Uint16 *text16 = (const Uint16 *) text;
        utf8_alloc = SDL_stack_alloc(Uint8, UCS2_to_UTF8_len(text16));
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        UCS2_to_UTF8(text16, utf8_alloc);
        text = (const char *)utf8_alloc;
    }

    
    if ((TTF_Size_Internal(font, text, STR_UTF8, &width, &height, &xstart, &ystart, NO_MEASUREMENT) < 0) || !width) {
        TTF_SetError("Text has zero width");
        goto failure;
    }

    
    fg.a = fg.a ? fg.a : SDL_ALPHA_OPAQUE;
    bg.a = bg.a ? bg.a : SDL_ALPHA_OPAQUE;

    
    if (render_mode == RENDER_SOLID) {
        textbuf = Create_Surface_Solid(width, height, fg, &color);
    } else if (render_mode == RENDER_SHADED) {
        textbuf = Create_Surface_Shaded(width, height, fg, bg, &color);
    } else { 
        textbuf = Create_Surface_Blended(width, height, fg, &color);
    }

    if (textbuf == NULL) {
        goto failure;
    }

    
    if (Render_Line(render_mode, font->render_subpixel, font, textbuf, xstart, ystart, fg.a) < 0) {
        goto failure;
    }

    
    if (TTF_HANDLE_STYLE_UNDERLINE(font)) {
        Draw_Line(font, textbuf, ystart + font->underline_top_row, width, font->line_thickness, color, render_mode);
    }

    if (TTF_HANDLE_STYLE_STRIKETHROUGH(font)) {
        Draw_Line(font, textbuf, ystart + font->strikethrough_top_row, width, font->line_thickness, color, render_mode);
    }

    if (utf8_alloc) {
        SDL_stack_free(utf8_alloc);
    }
    return textbuf;
failure:
    if (textbuf) {
        SDL_FreeSurface(textbuf);
    }
    if (utf8_alloc) {
        SDL_stack_free(utf8_alloc);
    }
    return NULL;
}

SDL_Surface* TTF_RenderText_Solid(TTF_Font *font, const char *text, SDL_Color fg)
{
    return TTF_Render_Internal(font, text, STR_TEXT, fg, fg , RENDER_SOLID);
}

SDL_Surface* TTF_RenderUTF8_Solid(TTF_Font *font, const char *text, SDL_Color fg)
{
    return TTF_Render_Internal(font, text, STR_UTF8, fg, fg , RENDER_SOLID);
}

SDL_Surface* TTF_RenderUNICODE_Solid(TTF_Font *font, const Uint16 *text, SDL_Color fg)
{
    return TTF_Render_Internal(font, (const char *)text, STR_UNICODE, fg, fg , RENDER_SOLID);
}

SDL_Surface* TTF_RenderGlyph_Solid(TTF_Font *font, Uint16 ch, SDL_Color fg)
{
    return TTF_RenderGlyph32_Solid(font, ch, fg);
}

SDL_Surface* TTF_RenderGlyph32_Solid(TTF_Font *font, Uint32 ch, SDL_Color fg)
{
    Uint8 utf8[7];

    TTF_CHECK_POINTER(font, NULL);

    if (!Char_to_UTF8(ch, utf8)) {
        return NULL;
    }

    return TTF_RenderUTF8_Solid(font, (char *)utf8, fg);
}

SDL_Surface* TTF_RenderText_Shaded(TTF_Font *font, const char *text, SDL_Color fg, SDL_Color bg)
{
    return TTF_Render_Internal(font, text, STR_TEXT, fg, bg, RENDER_SHADED);
}

SDL_Surface* TTF_RenderUTF8_Shaded(TTF_Font *font, const char *text, SDL_Color fg, SDL_Color bg)
{
    return TTF_Render_Internal(font, text, STR_UTF8, fg, bg, RENDER_SHADED);
}

SDL_Surface* TTF_RenderUNICODE_Shaded(TTF_Font *font, const Uint16 *text, SDL_Color fg, SDL_Color bg)
{
    return TTF_Render_Internal(font, (const char *)text, STR_UNICODE, fg, bg, RENDER_SHADED);
}

SDL_Surface* TTF_RenderGlyph_Shaded(TTF_Font *font, Uint16 ch, SDL_Color fg, SDL_Color bg)
{
    return TTF_RenderGlyph32_Shaded(font, ch, fg, bg);
}

SDL_Surface* TTF_RenderGlyph32_Shaded(TTF_Font *font, Uint32 ch, SDL_Color fg, SDL_Color bg)
{
    Uint8 utf8[7];

    TTF_CHECK_POINTER(font, NULL);

    if (!Char_to_UTF8(ch, utf8)) {
        return NULL;
    }

    return TTF_RenderUTF8_Shaded(font, (char *)utf8, fg, bg);
}

SDL_Surface* TTF_RenderText_Blended(TTF_Font *font, const char *text, SDL_Color fg)
{
    return TTF_Render_Internal(font, text, STR_TEXT, fg, fg , RENDER_BLENDED);
}

SDL_Surface* TTF_RenderUTF8_Blended(TTF_Font *font, const char *text, SDL_Color fg)
{
    return TTF_Render_Internal(font, text, STR_UTF8, fg, fg , RENDER_BLENDED);
}

SDL_Surface* TTF_RenderUNICODE_Blended(TTF_Font *font, const Uint16 *text, SDL_Color fg)
{
    return TTF_Render_Internal(font, (const char *)text, STR_UNICODE, fg, fg , RENDER_BLENDED);
}

static SDL_bool CharacterIsDelimiter(Uint32 c)
{
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        return SDL_TRUE;
    }
    return SDL_FALSE;
}

static SDL_bool CharacterIsNewLine(Uint32 c)
{
    if (c == '\n') {
        return SDL_TRUE;
    }
    return SDL_FALSE;
}

static SDL_Surface* TTF_Render_Wrapped_Internal(TTF_Font *font, const char *text, const str_type_t str_type, SDL_Color fg, SDL_Color bg, Uint32 wrapLength, const render_mode_t render_mode)
{
    Uint32 color;
    int width, height;
    SDL_Surface *textbuf = NULL;
    Uint8 *utf8_alloc = NULL;

    int i, numLines, rowHeight, lineskip;
    char **strLines = NULL, *text_cpy;

    TTF_CHECK_INITIALIZED(NULL);
    TTF_CHECK_POINTER(font, NULL);
    TTF_CHECK_POINTER(text, NULL);

    
    if (str_type == STR_TEXT) {
        utf8_alloc = SDL_stack_alloc(Uint8, LATIN1_to_UTF8_len(text));
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        LATIN1_to_UTF8(text, utf8_alloc);
        text_cpy = (char *)utf8_alloc;
    } else if (str_type == STR_UNICODE) {
        const Uint16 *text16 = (const Uint16 *) text;
        utf8_alloc = SDL_stack_alloc(Uint8, UCS2_to_UTF8_len(text16));
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        UCS2_to_UTF8(text16, utf8_alloc);
        text_cpy = (char *)utf8_alloc;
    } else {
        
        size_t str_len = SDL_strlen(text);
        utf8_alloc = SDL_stack_alloc(Uint8, str_len + 1);
        if (utf8_alloc == NULL) {
            SDL_OutOfMemory();
            goto failure;
        }
        SDL_memcpy(utf8_alloc, text, str_len + 1);
        text_cpy = (char *)utf8_alloc;
    }

    
    if ((TTF_SizeUTF8(font, text_cpy, &width, &height) < 0) || !width) {
        TTF_SetError("Text has zero width");
        goto failure;
    }

    
    if ((int)wrapLength < 0) {
        TTF_SetError("Invalid parameter 'wrapLength'");
        goto failure;
    }

    numLines = 1;

    if (*text_cpy) {
        int maxNumLines = 0;
        size_t textlen = SDL_strlen(text_cpy);
        numLines = 0;

        do {
            int extent = 0, max_count = 0, char_count = 0;
            size_t save_textlen = (size_t)(-1);
            char *save_text  = NULL;

            if (numLines >= maxNumLines) {
                char **saved = strLines;
                if (wrapLength == 0) {
                    maxNumLines += 32;
                } else {
                    maxNumLines += (width / wrapLength) + 1;
                }
                strLines = (char **)SDL_realloc(strLines, maxNumLines * sizeof (*strLines));
                if (strLines == NULL) {
                    strLines = saved;
                    SDL_OutOfMemory();
                    goto failure;
                }
            }

            strLines[numLines++] = text_cpy;

            if (TTF_MeasureUTF8(font, text_cpy, wrapLength, &extent, &max_count) < 0) {
                TTF_SetError("Error measure text");
                goto failure;
            }

            if (wrapLength != 0) {
                if (max_count == 0) {
                    max_count = 1;
                }
            }

            while (textlen > 0) {
                int inc = 0;
                int is_delim;
                Uint32 c = UTF8_getch(text_cpy, textlen, &inc);
                text_cpy += inc;
                textlen -= inc;

                if (c == UNICODE_BOM_NATIVE || c == UNICODE_BOM_SWAPPED) {
                    continue;
                }

                char_count += 1;

                
                is_delim = (wrapLength > 0) ?  CharacterIsDelimiter(c) : CharacterIsNewLine(c);

                
                if (is_delim) {
                    save_textlen = textlen;
                    save_text = text_cpy;
                    
                    if (c == '\n' || c == '\r') {
                        *(text_cpy - 1) = '\0';
                        break;
                    }
                }

                
                if (char_count == max_count) {
                    break;
                }
            }

            
            if (save_text && textlen) {
                text_cpy = save_text;
                textlen = save_textlen;
            }
        } while (textlen > 0);
    }

    lineskip = TTF_FontLineSkip(font);
    rowHeight = SDL_max(height, lineskip);

    if (wrapLength == 0) {
        
        if (numLines > 1) {
            width = 0;
            for (i = 0; i < numLines; i++) {
                char save_c = 0;
                int w, h;

                
                if (strLines) {
                    text = strLines[i];
                    if (i + 1 < numLines) {
                        save_c = strLines[i + 1][0];
                        strLines[i + 1][0] = '\0';
                    }
                }

                if (TTF_SizeUTF8(font, text, &w, &h) == 0) {
                    width = SDL_max(w, width);
                }

                
                if (strLines) {
                    if (i + 1 < numLines) {
                        strLines[i + 1][0] = save_c;
                    }
                }
            }
        }
    } else {
        if (numLines > 1) {
            width = wrapLength;
        } else {
            
            width = SDL_min((int)wrapLength, width);
        }
    }
    height = rowHeight + lineskip * (numLines - 1);

    
    fg.a = fg.a ? fg.a : SDL_ALPHA_OPAQUE;
    bg.a = bg.a ? bg.a : SDL_ALPHA_OPAQUE;

    
    if (render_mode == RENDER_SOLID) {
        textbuf = Create_Surface_Solid(width, height, fg, &color);
    } else if (render_mode == RENDER_SHADED) {
        textbuf = Create_Surface_Shaded(width, height, fg, bg, &color);
    } else { 
        textbuf = Create_Surface_Blended(width, height, fg, &color);
    }

    if (textbuf == NULL) {
        goto failure;
    }

    
    for (i = 0; i < numLines; i++) {
        int xstart, ystart, line_width;
        char save_c = 0;

        
        if (strLines) {
            text = strLines[i];
            if (i + 1 < numLines) {
                save_c = strLines[i + 1][0];
                strLines[i + 1][0] = '\0';
            }
        }

        
        if (TTF_Size_Internal(font, text, STR_UTF8, &line_width, NULL, &xstart, &ystart, NO_MEASUREMENT) < 0) {
            goto failure;
        }

        
        ystart += i * lineskip;

        
        if (Render_Line(render_mode, font->render_subpixel, font, textbuf, xstart, ystart, fg.a) < 0) {
            goto failure;
        }

        
        if (TTF_HANDLE_STYLE_UNDERLINE(font)) {
            Draw_Line(font, textbuf, ystart + font->underline_top_row, line_width, font->line_thickness, color, render_mode);
        }

        if (TTF_HANDLE_STYLE_STRIKETHROUGH(font)) {
            Draw_Line(font, textbuf, ystart + font->strikethrough_top_row, line_width, font->line_thickness, color, render_mode);
        }

        
        if (strLines) {
            if (i + 1 < numLines) {
                strLines[i + 1][0] = save_c;
            }
        }
    }

    if (strLines) {
        SDL_free(strLines);
    }
    if (utf8_alloc) {
        SDL_stack_free(utf8_alloc);
    }
    return textbuf;
failure:
    if (textbuf) {
        SDL_FreeSurface(textbuf);
    }
    if (strLines) {
        SDL_free(strLines);
    }
    if (utf8_alloc) {
        SDL_stack_free(utf8_alloc);
    }
    return NULL;
}

SDL_Surface* TTF_RenderText_Solid_Wrapped(TTF_Font *font, const char *text, SDL_Color fg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, text, STR_TEXT, fg, fg , wrapLength, RENDER_SOLID);
}

SDL_Surface* TTF_RenderUTF8_Solid_Wrapped(TTF_Font *font, const char *text, SDL_Color fg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, text, STR_UTF8, fg, fg , wrapLength, RENDER_SOLID);
}

SDL_Surface* TTF_RenderUNICODE_Solid_Wrapped(TTF_Font *font, const Uint16 *text, SDL_Color fg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, (const char *)text, STR_UNICODE, fg, fg , wrapLength, RENDER_SOLID);
}

SDL_Surface* TTF_RenderText_Shaded_Wrapped(TTF_Font *font, const char *text, SDL_Color fg, SDL_Color bg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, text, STR_TEXT, fg, bg, wrapLength, RENDER_SHADED);
}

SDL_Surface* TTF_RenderUTF8_Shaded_Wrapped(TTF_Font *font, const char *text, SDL_Color fg, SDL_Color bg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, text, STR_UTF8, fg, bg, wrapLength, RENDER_SHADED);
}

SDL_Surface* TTF_RenderUNICODE_Shaded_Wrapped(TTF_Font *font, const Uint16 *text, SDL_Color fg, SDL_Color bg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, (const char *)text, STR_UNICODE, fg, bg, wrapLength, RENDER_SHADED);
}

SDL_Surface* TTF_RenderText_Blended_Wrapped(TTF_Font *font, const char *text, SDL_Color fg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, text, STR_TEXT, fg, fg , wrapLength, RENDER_BLENDED);
}

SDL_Surface* TTF_RenderUTF8_Blended_Wrapped(TTF_Font *font, const char *text, SDL_Color fg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, text, STR_UTF8, fg, fg , wrapLength, RENDER_BLENDED);
}

SDL_Surface* TTF_RenderUNICODE_Blended_Wrapped(TTF_Font *font, const Uint16 *text, SDL_Color fg, Uint32 wrapLength)
{
    return TTF_Render_Wrapped_Internal(font, (const char *)text, STR_UNICODE, fg, fg , wrapLength, RENDER_BLENDED);
}

SDL_Surface* TTF_RenderGlyph_Blended(TTF_Font *font, Uint16 ch, SDL_Color fg)
{
    return TTF_RenderGlyph32_Blended(font, ch, fg);
}

SDL_Surface* TTF_RenderGlyph32_Blended(TTF_Font *font, Uint32 ch, SDL_Color fg)
{
    Uint8 utf8[7];

    TTF_CHECK_POINTER(font, NULL);

    if (!Char_to_UTF8(ch, utf8)) {
        return NULL;
    }

    return TTF_RenderUTF8_Blended(font, (char *)utf8, fg);
}

void TTF_SetFontStyle(TTF_Font *font, int style)
{
    int prev_style;
    long face_style;

    TTF_CHECK_POINTER(font,);

    prev_style = font->style;
    face_style = font->face->style_flags;

    
    if (face_style & FT_STYLE_FLAG_BOLD) {
        style &= ~TTF_STYLE_BOLD;
    }
    if (face_style & FT_STYLE_FLAG_ITALIC) {
        style &= ~TTF_STYLE_ITALIC;
    }

    font->style = style;

    TTF_initFontMetrics(font);

    
    if ((font->style | TTF_STYLE_NO_GLYPH_CHANGE) != (prev_style | TTF_STYLE_NO_GLYPH_CHANGE)) {
        Flush_Cache(font);
    }
}

int TTF_GetFontStyle(const TTF_Font *font)
{
    int style;
    long face_style;

    TTF_CHECK_POINTER(font, -1);

    style = font->style;
    face_style = font->face->style_flags;

    
    if (face_style & FT_STYLE_FLAG_BOLD) {
        style |= TTF_STYLE_BOLD;
    }
    if (face_style & FT_STYLE_FLAG_ITALIC) {
        style |= TTF_STYLE_ITALIC;
    }

    return style;
}

void TTF_SetFontOutline(TTF_Font *font, int outline)
{
    TTF_CHECK_POINTER(font,);

    font->outline_val = SDL_max(0, outline);
    TTF_initFontMetrics(font);
    Flush_Cache(font);
}

int TTF_GetFontOutline(const TTF_Font *font)
{
    TTF_CHECK_POINTER(font, -1);

    return font->outline_val;
}

void TTF_SetFontHinting(TTF_Font *font, int hinting)
{
    TTF_CHECK_POINTER(font,);

    if (hinting == TTF_HINTING_LIGHT || hinting == TTF_HINTING_LIGHT_SUBPIXEL) {
        font->ft_load_target = FT_LOAD_TARGET_LIGHT;
    } else if (hinting == TTF_HINTING_MONO) {
        font->ft_load_target = FT_LOAD_TARGET_MONO;
    } else if (hinting == TTF_HINTING_NONE) {
        font->ft_load_target = FT_LOAD_NO_HINTING;
    } else {
        font->ft_load_target = FT_LOAD_TARGET_NORMAL;
    }

    font->render_subpixel = (hinting == TTF_HINTING_LIGHT_SUBPIXEL) ? 1 : 0;

    
    hb_ft_font_set_load_flags(font->hb_font, FT_LOAD_DEFAULT | font->ft_load_target);


    Flush_Cache(font);
}

int TTF_GetFontHinting(const TTF_Font *font)
{
    TTF_CHECK_POINTER(font, -1);

    if (font->ft_load_target == FT_LOAD_TARGET_LIGHT) {
        if (font->render_subpixel == 0) {
            return TTF_HINTING_LIGHT;
        } else {
            return TTF_HINTING_LIGHT_SUBPIXEL;
        }
    } else if (font->ft_load_target == FT_LOAD_TARGET_MONO) {
        return TTF_HINTING_MONO;
    } else if (font->ft_load_target == FT_LOAD_NO_HINTING) {
        return TTF_HINTING_NONE;
    }
    return TTF_HINTING_NORMAL;
}

int TTF_SetFontSDF(TTF_Font *font, SDL_bool on_off)
{
    TTF_CHECK_POINTER(font, -1);

    font->render_sdf = on_off;
    Flush_Cache(font);
    return 0;

    TTF_SetError("SDL_ttf compiled without SDF support");
    return -1;

}

SDL_bool TTF_GetFontSDF(const TTF_Font *font)
{
    TTF_CHECK_POINTER(font, SDL_FALSE);
    return font->render_sdf;
}

void TTF_Quit(void)
{
    if (TTF_initialized) {
        if (--TTF_initialized == 0) {
            FT_Done_FreeType(library);
            library = NULL;
        }
    }
}

int TTF_WasInit(void)
{
    return TTF_initialized;
}


int TTF_GetFontKerningSize(TTF_Font *font, int prev_index, int index)
{
    FT_Vector delta;

    TTF_CHECK_POINTER(font, -1);

    FT_Get_Kerning(font->face, (FT_UInt)prev_index, (FT_UInt)index, FT_KERNING_DEFAULT, &delta);
    return (int)(delta.x >> 6);
}

int TTF_GetFontKerningSizeGlyphs(TTF_Font *font, Uint16 previous_ch, Uint16 ch)
{
    return TTF_GetFontKerningSizeGlyphs32(font, previous_ch, ch);
}

int TTF_GetFontKerningSizeGlyphs32(TTF_Font *font, Uint32 previous_ch, Uint32 ch)
{
    FT_Error error;
    c_glyph *prev_glyph, *glyph;
    FT_Vector delta;

    TTF_CHECK_POINTER(font, -1);

    if (ch == UNICODE_BOM_NATIVE || ch == UNICODE_BOM_SWAPPED) {
        return 0;
    }

    if (previous_ch == UNICODE_BOM_NATIVE || previous_ch == UNICODE_BOM_SWAPPED) {
        return 0;
    }

    if (Find_GlyphMetrics(font, ch, &glyph) < 0) {
        return -1;
    }

    if (Find_GlyphMetrics(font, previous_ch, &prev_glyph) < 0) {
        return -1;
    }

    error = FT_Get_Kerning(font->face, prev_glyph->index, glyph->index, FT_KERNING_DEFAULT, &delta);
    if (error) {
        TTF_SetFTError("Couldn't get glyph kerning", error);
        return -1;
    }
    return (int)(delta.x >> 6);
}


