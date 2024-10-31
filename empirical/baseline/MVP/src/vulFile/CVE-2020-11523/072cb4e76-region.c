





















HGDI_RGN gdi_CreateRectRgn(INT32 nLeftRect, INT32 nTopRect, INT32 nRightRect, INT32 nBottomRect)
{
	HGDI_RGN hRgn = (HGDI_RGN)calloc(1, sizeof(GDI_RGN));

	if (!hRgn)
		return NULL;

	hRgn->objectType = GDIOBJECT_REGION;
	hRgn->x = nLeftRect;
	hRgn->y = nTopRect;
	hRgn->w = nRightRect - nLeftRect + 1;
	hRgn->h = nBottomRect - nTopRect + 1;
	hRgn->null = FALSE;
	return hRgn;
}



HGDI_RECT gdi_CreateRect(INT32 xLeft, INT32 yTop, INT32 xRight, INT32 yBottom)
{
	HGDI_RECT hRect = (HGDI_RECT)calloc(1, sizeof(GDI_RECT));

	if (!hRect)
		return NULL;

	hRect->objectType = GDIOBJECT_RECT;
	hRect->left = xLeft;
	hRect->top = yTop;
	hRect->right = xRight;
	hRect->bottom = yBottom;
	return hRect;
}



INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn)
{
	rgn->x = rect->left;
	rgn->y = rect->top;
	rgn->w = rect->right - rect->left + 1;
	rgn->h = rect->bottom - rect->top + 1;
}



INLINE void gdi_CRectToRgn(INT32 left, INT32 top, INT32 right, INT32 bottom, HGDI_RGN rgn)
{
	rgn->x = left;
	rgn->y = top;
	rgn->w = right - left + 1;
	rgn->h = bottom - top + 1;
}



INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h)
{
	*x = rect->left;
	*y = rect->top;
	*w = rect->right - rect->left + 1;
	*h = rect->bottom - rect->top + 1;
}



INLINE void gdi_CRectToCRgn(INT32 left, INT32 top, INT32 right, INT32 bottom, INT32* x, INT32* y, INT32* w, INT32* h)
{
	*x = left;
	*y = top;
	*w = right - left + 1;
	*h = bottom - top + 1;
}



INLINE void gdi_RgnToRect(HGDI_RGN rgn, HGDI_RECT rect)
{
	rect->left = rgn->x;
	rect->top = rgn->y;
	rect->right = rgn->x + rgn->w - 1;
	rect->bottom = rgn->y + rgn->h - 1;
}



INLINE void gdi_CRgnToRect(INT64 x, INT64 y, INT32 w, INT32 h, HGDI_RECT rect)
{
	BOOL invalid = FALSE;
	const INT64 r = x + w - 1;
	const INT64 b = y + h - 1;
	rect->left = (x > 0) ? x : 0;
	rect->top = (y > 0) ? y : 0;
	rect->right = rect->left;
	rect->bottom = rect->top;

	if (r > 0)
		rect->right = r;
	else invalid = TRUE;

	if (b > 0)
		rect->bottom = b;
	else invalid = TRUE;

	if (invalid)
	{
		WLog_DBG(TAG, "Invisible rectangle %" PRId64 "x%" PRId64 "-%" PRId64 "x%" PRId64, x, y, r, b);
	}
}



INLINE void gdi_RgnToCRect(HGDI_RGN rgn, INT32* left, INT32* top, INT32* right, INT32* bottom)
{
	*left = rgn->x;
	*top = rgn->y;
	*right = rgn->x + rgn->w - 1;
	*bottom = rgn->y + rgn->h - 1;
}



INLINE void gdi_CRgnToCRect(INT32 x, INT32 y, INT32 w, INT32 h, INT32* left, INT32* top, INT32* right, INT32* bottom)
{
	*left = x;
	*top = y;
	*right = 0;

	if (w > 0)
		*right = x + w - 1;
	else WLog_ERR(TAG, "Invalid width");

	*bottom = 0;

	if (h > 0)
		*bottom = y + h - 1;
	else WLog_ERR(TAG, "Invalid height");
}



INLINE BOOL gdi_CopyOverlap(INT32 x, INT32 y, INT32 width, INT32 height, INT32 srcx, INT32 srcy)
{
	GDI_RECT dst;
	GDI_RECT src;
	gdi_CRgnToRect(x, y, width, height, &dst);
	gdi_CRgnToRect(srcx, srcy, width, height, &src);
	return (dst.right >= src.left && dst.left <= src.right && dst.bottom >= src.top && dst.top <= src.bottom)
	           ? TRUE : FALSE;
}



INLINE BOOL gdi_SetRect(HGDI_RECT rc, INT32 xLeft, INT32 yTop, INT32 xRight, INT32 yBottom)
{
	rc->left = xLeft;
	rc->top = yTop;
	rc->right = xRight;
	rc->bottom = yBottom;
	return TRUE;
}



INLINE BOOL gdi_SetRgn(HGDI_RGN hRgn, INT32 nXLeft, INT32 nYLeft, INT32 nWidth, INT32 nHeight)
{
	hRgn->x = nXLeft;
	hRgn->y = nYLeft;
	hRgn->w = nWidth;
	hRgn->h = nHeight;
	hRgn->null = FALSE;
	return TRUE;
}



INLINE BOOL gdi_SetRectRgn(HGDI_RGN hRgn, INT32 nLeftRect, INT32 nTopRect, INT32 nRightRect, INT32 nBottomRect)
{
	gdi_CRectToRgn(nLeftRect, nTopRect, nRightRect, nBottomRect, hRgn);
	hRgn->null = FALSE;
	return TRUE;
}



INLINE BOOL gdi_EqualRgn(HGDI_RGN hSrcRgn1, HGDI_RGN hSrcRgn2)
{
	if ((hSrcRgn1->x == hSrcRgn2->x) && (hSrcRgn1->y == hSrcRgn2->y) && (hSrcRgn1->w == hSrcRgn2->w) && (hSrcRgn1->h == hSrcRgn2->h))
	{
		return TRUE;
	}

	return FALSE;
}



INLINE BOOL gdi_CopyRect(HGDI_RECT dst, HGDI_RECT src)
{
	dst->left = src->left;
	dst->top = src->top;
	dst->right = src->right;
	dst->bottom = src->bottom;
	return TRUE;
}



INLINE BOOL gdi_PtInRect(HGDI_RECT rc, INT32 x, INT32 y)
{
	
	if (x >= rc->left && x <= rc->right)
	{
		if (y >= rc->top && y <= rc->bottom)
		{
			return TRUE;
		}
	}

	return FALSE;
}



INLINE BOOL gdi_InvalidateRegion(HGDI_DC hdc, INT32 x, INT32 y, INT32 w, INT32 h)
{
	GDI_RECT inv;
	GDI_RECT rgn;
	HGDI_RGN invalid;
	HGDI_RGN cinvalid;

	if (!hdc->hwnd)
		return TRUE;

	if (!hdc->hwnd->invalid)
		return TRUE;

	if (w == 0 || h == 0)
		return TRUE;

	cinvalid = hdc->hwnd->cinvalid;

	if ((hdc->hwnd->ninvalid + 1) > (INT64)hdc->hwnd->count)
	{
		int new_cnt;
		HGDI_RGN new_rgn;
		new_cnt = hdc->hwnd->count * 2;
		new_rgn = (HGDI_RGN)realloc(cinvalid, sizeof(GDI_RGN) * new_cnt);

		if (!new_rgn)
			return FALSE;

		hdc->hwnd->count = new_cnt;
		cinvalid = new_rgn;
	}

	gdi_SetRgn(&cinvalid[hdc->hwnd->ninvalid++], x, y, w, h);
	hdc->hwnd->cinvalid = cinvalid;
	invalid = hdc->hwnd->invalid;

	if (invalid->null)
	{
		invalid->x = x;
		invalid->y = y;
		invalid->w = w;
		invalid->h = h;
		invalid->null = FALSE;
		return TRUE;
	}

	gdi_CRgnToRect(x, y, w, h, &rgn);
	gdi_RgnToRect(invalid, &inv);

	if (rgn.left < inv.left)
		inv.left = rgn.left;

	if (rgn.top < inv.top)
		inv.top = rgn.top;

	if (rgn.right > inv.right)
		inv.right = rgn.right;

	if (rgn.bottom > inv.bottom)
		inv.bottom = rgn.bottom;

	gdi_RectToRgn(&inv, invalid);
	return TRUE;
}
