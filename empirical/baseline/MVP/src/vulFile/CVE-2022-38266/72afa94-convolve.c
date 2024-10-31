










    
LEPT_DLL l_int32  ConvolveSamplingFactX = 1;
LEPT_DLL l_int32  ConvolveSamplingFactY = 1;

    
static void blockconvLow(l_uint32 *data, l_int32 w, l_int32 h, l_int32 wpl, l_uint32 *dataa, l_int32 wpla, l_int32 wc, l_int32 hc);

static void blockconvAccumLow(l_uint32 *datad, l_int32 w, l_int32 h, l_int32 wpld, l_uint32 *datas, l_int32 d, l_int32 wpls);

static void blocksumLow(l_uint32 *datad, l_int32 w, l_int32 h, l_int32 wpl, l_uint32 *dataa, l_int32 wpla, l_int32 wc, l_int32 hc);




PIX  * pixBlockconv(PIX     *pix, l_int32  wc, l_int32  hc)


{
l_int32  w, h, d;
PIX     *pixs, *pixd, *pixr, *pixrc, *pixg, *pixgc, *pixb, *pixbc;

    PROCNAME("pixBlockconv");

    if (!pix)
        return (PIX *)ERROR_PTR("pix not defined", procName, NULL);
    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    pixGetDimensions(pix, &w, &h, &d);
    if (w < 2 * wc + 1 || h < 2 * hc + 1) {
        wc = L_MIN(wc, (w - 1) / 2);
        hc = L_MIN(hc, (h - 1) / 2);
        L_WARNING("kernel too large; reducing!\n", procName);
        L_INFO("wc = %d, hc = %d\n", procName, wc, hc);
    }
    if (wc == 0 && hc == 0)   
        return pixCopy(NULL, pix);

        
    if ((d == 2 || d == 4 || d == 8) && pixGetColormap(pix)) {
        L_WARNING("pix has colormap; removing\n", procName);
        pixs = pixRemoveColormap(pix, REMOVE_CMAP_BASED_ON_SRC);
        d = pixGetDepth(pixs);
    } else {
        pixs = pixClone(pix);
    }

    if (d != 8 && d != 32) {
        pixDestroy(&pixs);
        return (PIX *)ERROR_PTR("depth not 8 or 32 bpp", procName, NULL);
    }

    if (d == 8) {
        pixd = pixBlockconvGray(pixs, NULL, wc, hc);
    } else { 
        pixr = pixGetRGBComponent(pixs, COLOR_RED);
        pixrc = pixBlockconvGray(pixr, NULL, wc, hc);
        pixDestroy(&pixr);
        pixg = pixGetRGBComponent(pixs, COLOR_GREEN);
        pixgc = pixBlockconvGray(pixg, NULL, wc, hc);
        pixDestroy(&pixg);
        pixb = pixGetRGBComponent(pixs, COLOR_BLUE);
        pixbc = pixBlockconvGray(pixb, NULL, wc, hc);
        pixDestroy(&pixb);
        pixd = pixCreateRGBImage(pixrc, pixgc, pixbc);
        pixDestroy(&pixrc);
        pixDestroy(&pixgc);
        pixDestroy(&pixbc);
    }

    pixDestroy(&pixs);
    return pixd;
}




PIX * pixBlockconvGray(PIX     *pixs, PIX     *pixacc, l_int32  wc, l_int32  hc)



{
l_int32    w, h, d, wpl, wpla;
l_uint32  *datad, *dataa;
PIX       *pixd, *pixt;

    PROCNAME("pixBlockconvGray");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8)
        return (PIX *)ERROR_PTR("pixs not 8 bpp", procName, NULL);
    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    if (wc == 0 && hc == 0)   
        return pixCopy(NULL, pixs);
    if (w < 2 * wc + 1 || h < 2 * hc + 1) {
        L_WARNING("kernel too large; returning a copy\n", procName);
        L_INFO("w = %d, wc = %d, h = %d, hc = %d\n", procName, w, wc, h, hc);
        return pixCopy(NULL, pixs);
    }

    if (pixacc) {
        if (pixGetDepth(pixacc) == 32) {
            pixt = pixClone(pixacc);
        } else {
            L_WARNING("pixacc not 32 bpp; making new one\n", procName);
            if ((pixt = pixBlockconvAccum(pixs)) == NULL)
                return (PIX *)ERROR_PTR("pixt not made", procName, NULL);
        }
    } else {
        if ((pixt = pixBlockconvAccum(pixs)) == NULL)
            return (PIX *)ERROR_PTR("pixt not made", procName, NULL);
    }

    if ((pixd = pixCreateTemplate(pixs)) == NULL) {
        pixDestroy(&pixt);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }

    pixSetPadBits(pixt, 0);
    wpl = pixGetWpl(pixd);
    wpla = pixGetWpl(pixt);
    datad = pixGetData(pixd);
    dataa = pixGetData(pixt);
    blockconvLow(datad, w, h, wpl, dataa, wpla, wc, hc);

    pixDestroy(&pixt);
    return pixd;
}



static void blockconvLow(l_uint32  *data, l_int32    w, l_int32    h, l_int32    wpl, l_uint32  *dataa, l_int32    wpla, l_int32    wc, l_int32    hc)







{
l_int32    i, j, imax, imin, jmax, jmin;
l_int32    wn, hn, fwc, fhc, wmwc, hmhc;
l_float32  norm, normh, normw;
l_uint32   val;
l_uint32  *linemina, *linemaxa, *line;

    PROCNAME("blockconvLow");

    wmwc = w - wc;
    hmhc = h - hc;
    if (wmwc <= 0 || hmhc <= 0) {
        L_ERROR("wc >= w || hc >=h\n", procName);
        return;
    }
    fwc = 2 * wc + 1;
    fhc = 2 * hc + 1;
    norm = 1.0 / ((l_float32)(fwc) * fhc);

        
    for (i = 0; i < h; i++) {
        imin = L_MAX(i - 1 - hc, 0);
        imax = L_MIN(i + hc, h - 1);
        line = data + wpl * i;
        linemina = dataa + wpla * imin;
        linemaxa = dataa + wpla * imax;
        for (j = 0; j < w; j++) {
            jmin = L_MAX(j - 1 - wc, 0);
            jmax = L_MIN(j + wc, w - 1);
            val = linemaxa[jmax] - linemaxa[jmin] + linemina[jmin] - linemina[jmax];
            val = (l_uint8)(norm * val + 0.5);  
            SET_DATA_BYTE(line, j, val);
        }
    }

        
    for (i = 0; i <= hc; i++) {    
        hn = L_MAX(1, hc + i);
        normh = (l_float32)fhc / (l_float32)hn;   
        line = data + wpl * i;
        for (j = 0; j <= wc; j++) {
            wn = L_MAX(1, wc + j);
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normh * normw, 255);
            SET_DATA_BYTE(line, j, val);
        }
        for (j = wc + 1; j < wmwc; j++) {
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normh, 255);
            SET_DATA_BYTE(line, j, val);
        }
        for (j = wmwc; j < w; j++) {
            wn = wc + w - j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normh * normw, 255);
            SET_DATA_BYTE(line, j, val);
        }
    }

    for (i = hmhc; i < h; i++) {  
        hn = hc + h - i;
        normh = (l_float32)fhc / (l_float32)hn;   
        line = data + wpl * i;
        for (j = 0; j <= wc; j++) {
            wn = wc + j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normh * normw, 255);
            SET_DATA_BYTE(line, j, val);
        }
        for (j = wc + 1; j < wmwc; j++) {
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normh, 255);
            SET_DATA_BYTE(line, j, val);
        }
        for (j = wmwc; j < w; j++) {
            wn = wc + w - j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normh * normw, 255);
            SET_DATA_BYTE(line, j, val);
        }
    }

    for (i = hc + 1; i < hmhc; i++) {    
        line = data + wpl * i;
        for (j = 0; j <= wc; j++) {   
            wn = wc + j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normw, 255);
            SET_DATA_BYTE(line, j, val);
        }
        for (j = wmwc; j < w; j++) {   
            wn = wc + w - j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(line, j);
            val = (l_uint8)L_MIN(val * normw, 255);
            SET_DATA_BYTE(line, j, val);
        }
    }
}




PIX * pixBlockconvAccum(PIX  *pixs)
{
l_int32    w, h, d, wpls, wpld;
l_uint32  *datas, *datad;
PIX       *pixd;

    PROCNAME("pixBlockconvAccum");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);

    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 1 && d != 8 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 1, 8 or 32 bpp", procName, NULL);
    if ((pixd = pixCreate(w, h, 32)) == NULL)
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);

    datas = pixGetData(pixs);
    datad = pixGetData(pixd);
    wpls = pixGetWpl(pixs);
    wpld = pixGetWpl(pixd);
    blockconvAccumLow(datad, w, h, wpld, datas, d, wpls);

    return pixd;
}



static void blockconvAccumLow(l_uint32  *datad, l_int32    w, l_int32    h, l_int32    wpld, l_uint32  *datas, l_int32    d, l_int32    wpls)






{
l_uint8    val;
l_int32    i, j;
l_uint32   val32;
l_uint32  *lines, *lined, *linedp;

    PROCNAME("blockconvAccumLow");

    lines = datas;
    lined = datad;

    if (d == 1) {
            
        for (j = 0; j < w; j++) {
            val = GET_DATA_BIT(lines, j);
            if (j == 0)
                lined[0] = val;
            else lined[j] = lined[j - 1] + val;
        }

            
        for (i = 1; i < h; i++) {
            lines = datas + i * wpls;
            lined = datad + i * wpld;  
            linedp = lined - wpld;   
            for (j = 0; j < w; j++) {
                val = GET_DATA_BIT(lines, j);
                if (j == 0)
                    lined[0] = val + linedp[0];
                else lined[j] = val + lined[j - 1] + linedp[j] - linedp[j - 1];
            }
        }
    } else if (d == 8) {
            
        for (j = 0; j < w; j++) {
            val = GET_DATA_BYTE(lines, j);
            if (j == 0)
                lined[0] = val;
            else lined[j] = lined[j - 1] + val;
        }

            
        for (i = 1; i < h; i++) {
            lines = datas + i * wpls;
            lined = datad + i * wpld;  
            linedp = lined - wpld;   
            for (j = 0; j < w; j++) {
                val = GET_DATA_BYTE(lines, j);
                if (j == 0)
                    lined[0] = val + linedp[0];
                else lined[j] = val + lined[j - 1] + linedp[j] - linedp[j - 1];
            }
        }
    } else if (d == 32) {
            
        for (j = 0; j < w; j++) {
            val32 = lines[j];
            if (j == 0)
                lined[0] = val32;
            else lined[j] = lined[j - 1] + val32;
        }

            
        for (i = 1; i < h; i++) {
            lines = datas + i * wpls;
            lined = datad + i * wpld;  
            linedp = lined - wpld;   
            for (j = 0; j < w; j++) {
                val32 = lines[j];
                if (j == 0)
                    lined[0] = val32 + linedp[0];
                else lined[j] = val32 + lined[j - 1] + linedp[j] - linedp[j - 1];
            }
        }
    } else {
        L_ERROR("depth not 1, 8 or 32 bpp\n", procName);
    }
}




PIX * pixBlockconvGrayUnnormalized(PIX     *pixs, l_int32  wc, l_int32  hc)


{
l_int32    i, j, w, h, d, wpla, wpld, jmax;
l_uint32  *linemina, *linemaxa, *lined, *dataa, *datad;
PIX       *pixsb, *pixacc, *pixd;

    PROCNAME("pixBlockconvGrayUnnormalized");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8)
        return (PIX *)ERROR_PTR("pixs not 8 bpp", procName, NULL);
    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    if (w < 2 * wc + 1 || h < 2 * hc + 1) {
        wc = L_MIN(wc, (w - 1) / 2);
        hc = L_MIN(hc, (h - 1) / 2);
        L_WARNING("kernel too large; reducing!\n", procName);
        L_INFO("wc = %d, hc = %d\n", procName, wc, hc);
    }
    if (wc == 0 && hc == 0)   
        return pixCopy(NULL, pixs);

    if ((pixsb = pixAddMirroredBorder(pixs, wc + 1, wc, hc + 1, hc)) == NULL)
        return (PIX *)ERROR_PTR("pixsb not made", procName, NULL);
    pixacc = pixBlockconvAccum(pixsb);
    pixDestroy(&pixsb);
    if (!pixacc)
        return (PIX *)ERROR_PTR("pixacc not made", procName, NULL);
    if ((pixd = pixCreate(w, h, 32)) == NULL) {
        pixDestroy(&pixacc);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }

    wpla = pixGetWpl(pixacc);
    wpld = pixGetWpl(pixd);
    datad = pixGetData(pixd);
    dataa = pixGetData(pixacc);
    for (i = 0; i < h; i++) {
        lined = datad + i * wpld;
        linemina = dataa + i * wpla;
        linemaxa = dataa + (i + 2 * hc + 1) * wpla;
        for (j = 0; j < w; j++) {
            jmax = j + 2 * wc + 1;
            lined[j] = linemaxa[jmax] - linemaxa[j] - linemina[jmax] + linemina[j];
        }
    }

    pixDestroy(&pixacc);
    return pixd;
}




PIX * pixBlockconvTiled(PIX     *pix, l_int32  wc, l_int32  hc, l_int32  nx, l_int32  ny)




{
l_int32     i, j, w, h, d, xrat, yrat;
PIX        *pixs, *pixd, *pixc, *pixt;
PIX        *pixr, *pixrc, *pixg, *pixgc, *pixb, *pixbc;
PIXTILING  *pt;

    PROCNAME("pixBlockconvTiled");

    if (!pix)
        return (PIX *)ERROR_PTR("pix not defined", procName, NULL);
    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    pixGetDimensions(pix, &w, &h, &d);
    if (w < 2 * wc + 3 || h < 2 * hc + 3) {
        wc = L_MAX(0, L_MIN(wc, (w - 3) / 2));
        hc = L_MAX(0, L_MIN(hc, (h - 3) / 2));
        L_WARNING("kernel too large; reducing!\n", procName);
        L_INFO("wc = %d, hc = %d\n", procName, wc, hc);
    }
    if (wc == 0 && hc == 0)   
        return pixCopy(NULL, pix);
    if (nx <= 1 && ny <= 1)
        return pixBlockconv(pix, wc, hc);

        
    xrat = w / nx;
    yrat = h / ny;
    if (xrat < wc + 2) {
        nx = w / (wc + 2);
        L_WARNING("tile width too small; nx reduced to %d\n", procName, nx);
    }
    if (yrat < hc + 2) {
        ny = h / (hc + 2);
        L_WARNING("tile height too small; ny reduced to %d\n", procName, ny);
    }

        
    if ((d == 2 || d == 4 || d == 8) && pixGetColormap(pix)) {
        L_WARNING("pix has colormap; removing\n", procName);
        pixs = pixRemoveColormap(pix, REMOVE_CMAP_BASED_ON_SRC);
        d = pixGetDepth(pixs);
    } else {
        pixs = pixClone(pix);
    }

    if (d != 8 && d != 32) {
        pixDestroy(&pixs);
        return (PIX *)ERROR_PTR("depth not 8 or 32 bpp", procName, NULL);
    }

       
    if ((pixd = pixCreateTemplate(pixs)) == NULL) {
        pixDestroy(&pixs);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }
    pt = pixTilingCreate(pixs, nx, ny, 0, 0, wc + 2, hc + 2);
    for (i = 0; i < ny; i++) {
        for (j = 0; j < nx; j++) {
            pixt = pixTilingGetTile(pt, i, j);

                
            if (d == 8) {
                pixc = pixBlockconvGrayTile(pixt, NULL, wc, hc);
            } else { 
                pixr = pixGetRGBComponent(pixt, COLOR_RED);
                pixrc = pixBlockconvGrayTile(pixr, NULL, wc, hc);
                pixDestroy(&pixr);
                pixg = pixGetRGBComponent(pixt, COLOR_GREEN);
                pixgc = pixBlockconvGrayTile(pixg, NULL, wc, hc);
                pixDestroy(&pixg);
                pixb = pixGetRGBComponent(pixt, COLOR_BLUE);
                pixbc = pixBlockconvGrayTile(pixb, NULL, wc, hc);
                pixDestroy(&pixb);
                pixc = pixCreateRGBImage(pixrc, pixgc, pixbc);
                pixDestroy(&pixrc);
                pixDestroy(&pixgc);
                pixDestroy(&pixbc);
            }

            pixTilingPaintTile(pixd, i, j, pixc, pt);
            pixDestroy(&pixt);
            pixDestroy(&pixc);
        }
    }

    pixDestroy(&pixs);
    pixTilingDestroy(&pt);
    return pixd;
}



PIX * pixBlockconvGrayTile(PIX     *pixs, PIX     *pixacc, l_int32  wc, l_int32  hc)



{
l_int32    w, h, d, wd, hd, i, j, imin, imax, jmin, jmax, wplt, wpld;
l_float32  norm;
l_uint32   val;
l_uint32  *datat, *datad, *lined, *linemint, *linemaxt;
PIX       *pixt, *pixd;

    PROCNAME("pixBlockconvGrayTile");

    if (!pixs)
        return (PIX *)ERROR_PTR("pix not defined", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8)
        return (PIX *)ERROR_PTR("pixs not 8 bpp", procName, NULL);
    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    if (w < 2 * wc + 3 || h < 2 * hc + 3) {
        wc = L_MAX(0, L_MIN(wc, (w - 3) / 2));
        hc = L_MAX(0, L_MIN(hc, (h - 3) / 2));
        L_WARNING("kernel too large; reducing!\n", procName);
        L_INFO("wc = %d, hc = %d\n", procName, wc, hc);
    }
    if (wc == 0 && hc == 0)
        return pixCopy(NULL, pixs);
    wd = w - 2 * wc;
    hd = h - 2 * hc;

    if (pixacc) {
        if (pixGetDepth(pixacc) == 32) {
            pixt = pixClone(pixacc);
        } else {
            L_WARNING("pixacc not 32 bpp; making new one\n", procName);
            if ((pixt = pixBlockconvAccum(pixs)) == NULL)
                return (PIX *)ERROR_PTR("pixt not made", procName, NULL);
        }
    } else {
        if ((pixt = pixBlockconvAccum(pixs)) == NULL)
            return (PIX *)ERROR_PTR("pixt not made", procName, NULL);
    }

    if ((pixd = pixCreateTemplate(pixs)) == NULL) {
        pixDestroy(&pixt);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }
    datat = pixGetData(pixt);
    wplt = pixGetWpl(pixt);
    datad = pixGetData(pixd);
    wpld = pixGetWpl(pixd);
    norm = 1. / (l_float32)((2 * wc + 1) * (2 * hc + 1));

        
    for (i = hc; i < hc + hd - 2; i++) {
        imin = L_MAX(i - hc - 1, 0);
        imax = L_MIN(i + hc, h - 1);
        lined = datad + i * wpld;
        linemint = datat + imin * wplt;
        linemaxt = datat + imax * wplt;
        for (j = wc; j < wc + wd - 2; j++) {
            jmin = L_MAX(j - wc - 1, 0);
            jmax = L_MIN(j + wc, w - 1);
            val = linemaxt[jmax] - linemaxt[jmin] + linemint[jmin] - linemint[jmax];
            val = (l_uint8)(norm * val + 0.5);
            SET_DATA_BYTE(lined, j, val);
        }
    }

    pixDestroy(&pixt);
    return pixd;
}




l_ok pixWindowedStats(PIX     *pixs, l_int32  wc, l_int32  hc, l_int32  hasborder, PIX    **ppixm, PIX    **ppixms, FPIX   **pfpixv, FPIX   **pfpixrv)







{
PIX  *pixb, *pixm, *pixms;

    PROCNAME("pixWindowedStats");

    if (!ppixm && !ppixms && !pfpixv && !pfpixrv)
        return ERROR_INT("no output requested", procName, 1);
    if (ppixm) *ppixm = NULL;
    if (ppixms) *ppixms = NULL;
    if (pfpixv) *pfpixv = NULL;
    if (pfpixrv) *pfpixrv = NULL;
    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not defined or not 8 bpp", procName, 1);
    if (wc < 2 || hc < 2)
        return ERROR_INT("wc and hc not >= 2", procName, 1);

        
    if (!hasborder)
        pixb = pixAddBorderGeneral(pixs, wc + 1, wc + 1, hc + 1, hc + 1, 0);
    else pixb = pixClone(pixs);

    if (!pfpixv && !pfpixrv) {
        if (ppixm) *ppixm = pixWindowedMean(pixb, wc, hc, 1, 1);
        if (ppixms) *ppixms = pixWindowedMeanSquare(pixb, wc, hc, 1);
        pixDestroy(&pixb);
        return 0;
    }

    pixm = pixWindowedMean(pixb, wc, hc, 1, 1);
    pixms = pixWindowedMeanSquare(pixb, wc, hc, 1);
    pixWindowedVariance(pixm, pixms, pfpixv, pfpixrv);
    if (ppixm)
        *ppixm = pixm;
    else pixDestroy(&pixm);
    if (ppixms)
        *ppixms = pixms;
    else pixDestroy(&pixms);
    pixDestroy(&pixb);
    return 0;
}



PIX * pixWindowedMean(PIX     *pixs, l_int32  wc, l_int32  hc, l_int32  hasborder, l_int32  normflag)




{
l_int32    i, j, w, h, d, wd, hd, wplc, wpld, wincr, hincr;
l_uint32   val;
l_uint32  *datac, *datad, *linec1, *linec2, *lined;
l_float32  norm;
PIX       *pixb, *pixc, *pixd;

    PROCNAME("pixWindowedMean");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    d = pixGetDepth(pixs);
    if (d != 8 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 8 or 32 bpp", procName, NULL);
    if (wc < 2 || hc < 2)
        return (PIX *)ERROR_PTR("wc and hc not >= 2", procName, NULL);

    pixb = pixc = pixd = NULL;

        
    if (!hasborder)
        pixb = pixAddBorderGeneral(pixs, wc + 1, wc + 1, hc + 1, hc + 1, 0);
    else pixb = pixClone(pixs);

        
    if ((pixc = pixBlockconvAccum(pixb)) == NULL) {
        L_ERROR("pixc not made\n", procName);
        goto cleanup;
    }
    wplc = pixGetWpl(pixc);
    datac = pixGetData(pixc);

        
    pixGetDimensions(pixb, &w, &h, NULL);
    wd = w - 2 * (wc + 1);
    hd = h - 2 * (hc + 1);
    if (wd < 2 || hd < 2) {
        L_ERROR("w or h is too small for the kernel\n", procName);
        goto cleanup;
    }
    if ((pixd = pixCreate(wd, hd, d)) == NULL) {
        L_ERROR("pixd not made\n", procName);
        goto cleanup;
    }
    wpld = pixGetWpl(pixd);
    datad = pixGetData(pixd);

    wincr = 2 * wc + 1;
    hincr = 2 * hc + 1;
    norm = 1.0;  
    if (normflag)
        norm = 1.0 / ((l_float32)(wincr) * hincr);
    for (i = 0; i < hd; i++) {
        linec1 = datac + i * wplc;
        linec2 = datac + (i + hincr) * wplc;
        lined = datad + i * wpld;
        for (j = 0; j < wd; j++) {
            val = linec2[j + wincr] - linec2[j] - linec1[j + wincr] + linec1[j];
            if (d == 8) {
                val = (l_uint8)(norm * val);
                SET_DATA_BYTE(lined, j, val);
            } else {  
                val = (l_uint32)(norm * val);
                lined[j] = val;
            }
        }
    }

cleanup:
    pixDestroy(&pixb);
    pixDestroy(&pixc);
    return pixd;
}



PIX * pixWindowedMeanSquare(PIX     *pixs, l_int32  wc, l_int32  hc, l_int32  hasborder)



{
l_int32     i, j, w, h, wd, hd, wpl, wpld, wincr, hincr;
l_uint32    ival;
l_uint32   *datad, *lined;
l_float64   norm;
l_float64   val;
l_float64  *data, *line1, *line2;
DPIX       *dpix;
PIX        *pixb, *pixd;

    PROCNAME("pixWindowedMeanSquare");

    if (!pixs || (pixGetDepth(pixs) != 8))
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);
    if (wc < 2 || hc < 2)
        return (PIX *)ERROR_PTR("wc and hc not >= 2", procName, NULL);

    pixd = NULL;

        
    if (!hasborder)
        pixb = pixAddBorderGeneral(pixs, wc + 1, wc + 1, hc + 1, hc + 1, 0);
    else pixb = pixClone(pixs);

    if ((dpix = pixMeanSquareAccum(pixb)) == NULL) {
        L_ERROR("dpix not made\n", procName);
        goto cleanup;
    }
    wpl = dpixGetWpl(dpix);
    data = dpixGetData(dpix);

        
    pixGetDimensions(pixb, &w, &h, NULL);
    wd = w - 2 * (wc + 1);
    hd = h - 2 * (hc + 1);
    if (wd < 2 || hd < 2) {
        L_ERROR("w or h too small for kernel\n", procName);
        goto cleanup;
    }
    if ((pixd = pixCreate(wd, hd, 32)) == NULL) {
        L_ERROR("pixd not made\n", procName);
        goto cleanup;
    }
    wpld = pixGetWpl(pixd);
    datad = pixGetData(pixd);

    wincr = 2 * wc + 1;
    hincr = 2 * hc + 1;
    norm = 1.0 / ((l_float32)(wincr) * hincr);
    for (i = 0; i < hd; i++) {
        line1 = data + i * wpl;
        line2 = data + (i + hincr) * wpl;
        lined = datad + i * wpld;
        for (j = 0; j < wd; j++) {
            val = line2[j + wincr] - line2[j] - line1[j + wincr] + line1[j];
            ival = (l_uint32)(norm * val + 0.5);  
            lined[j] = ival;
        }
    }

cleanup:
    dpixDestroy(&dpix);
    pixDestroy(&pixb);
    return pixd;
}



l_ok pixWindowedVariance(PIX    *pixm, PIX    *pixms, FPIX  **pfpixv, FPIX  **pfpixrv)



{
l_int32     i, j, w, h, ws, hs, ds, wplm, wplms, wplv, wplrv, valm, valms;
l_float32   var;
l_uint32   *linem, *linems, *datam, *datams;
l_float32  *linev, *linerv, *datav, *datarv;
FPIX       *fpixv, *fpixrv;  

    PROCNAME("pixWindowedVariance");

    if (!pfpixv && !pfpixrv)
        return ERROR_INT("no output requested", procName, 1);
    if (pfpixv) *pfpixv = NULL;
    if (pfpixrv) *pfpixrv = NULL;
    if (!pixm || pixGetDepth(pixm) != 8)
        return ERROR_INT("pixm undefined or not 8 bpp", procName, 1);
    if (!pixms || pixGetDepth(pixms) != 32)
        return ERROR_INT("pixms undefined or not 32 bpp", procName, 1);
    pixGetDimensions(pixm, &w, &h, NULL);
    pixGetDimensions(pixms, &ws, &hs, &ds);
    if (w != ws || h != hs)
        return ERROR_INT("pixm and pixms sizes differ", procName, 1);

    if (pfpixv) {
        fpixv = fpixCreate(w, h);
        *pfpixv = fpixv;
        wplv = fpixGetWpl(fpixv);
        datav = fpixGetData(fpixv);
    }
    if (pfpixrv) {
        fpixrv = fpixCreate(w, h);
        *pfpixrv = fpixrv;
        wplrv = fpixGetWpl(fpixrv);
        datarv = fpixGetData(fpixrv);
    }

    wplm = pixGetWpl(pixm);
    wplms = pixGetWpl(pixms);
    datam = pixGetData(pixm);
    datams = pixGetData(pixms);
    for (i = 0; i < h; i++) {
        linem = datam + i * wplm;
        linems = datams + i * wplms;
        if (pfpixv)
            linev = datav + i * wplv;
        if (pfpixrv)
            linerv = datarv + i * wplrv;
        for (j = 0; j < w; j++) {
            valm = GET_DATA_BYTE(linem, j);
            if (ds == 8)
                valms = GET_DATA_BYTE(linems, j);
            else   valms = (l_int32)linems[j];
            var = (l_float32)valms - (l_float32)valm * valm;
            if (pfpixv)
                linev[j] = var;
            if (pfpixrv)
                linerv[j] = (l_float32)sqrt(var);
        }
    }

    return 0;
}



DPIX * pixMeanSquareAccum(PIX  *pixs)
{
l_int32     i, j, w, h, wpl, wpls, val;
l_uint32   *datas, *lines;
l_float64  *data, *line, *linep;
DPIX       *dpix;

    PROCNAME("pixMeanSquareAccum");


    if (!pixs || (pixGetDepth(pixs) != 8))
        return (DPIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);
    pixGetDimensions(pixs, &w, &h, NULL);
    if ((dpix = dpixCreate(w, h)) ==  NULL)
        return (DPIX *)ERROR_PTR("dpix not made", procName, NULL);

    datas = pixGetData(pixs);
    wpls = pixGetWpl(pixs);
    data = dpixGetData(dpix);
    wpl = dpixGetWpl(dpix);

    lines = datas;
    line = data;
    for (j = 0; j < w; j++) {   
        val = GET_DATA_BYTE(lines, j);
        if (j == 0)
            line[0] = (l_float64)(val) * val;
        else line[j] = line[j - 1] + (l_float64)(val) * val;
    }

        
    for (i = 1; i < h; i++) {
        lines = datas + i * wpls;
        line = data + i * wpl;  
        linep = line - wpl;;  
        for (j = 0; j < w; j++) {
            val = GET_DATA_BYTE(lines, j);
            if (j == 0)
                line[0] = linep[0] + (l_float64)(val) * val;
            else line[j] = line[j - 1] + linep[j] - linep[j - 1] + (l_float64)(val) * val;

        }
    }

    return dpix;
}




PIX * pixBlockrank(PIX       *pixs, PIX       *pixacc, l_int32    wc, l_int32    hc, l_float32  rank)




{
l_int32  w, h, d, thresh;
PIX     *pixt, *pixd;

    PROCNAME("pixBlockrank");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 1)
        return (PIX *)ERROR_PTR("pixs not 1 bpp", procName, NULL);
    if (rank < 0.0 || rank > 1.0)
        return (PIX *)ERROR_PTR("rank must be in [0.0, 1.0]", procName, NULL);

    if (rank == 0.0) {
        pixd = pixCreateTemplate(pixs);
        pixSetAll(pixd);
        return pixd;
    }

    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    if (w < 2 * wc + 1 || h < 2 * hc + 1) {
        wc = L_MIN(wc, (w - 1) / 2);
        hc = L_MIN(hc, (h - 1) / 2);
        L_WARNING("kernel too large; reducing!\n", procName);
        L_INFO("wc = %d, hc = %d\n", procName, wc, hc);
    }
    if (wc == 0 && hc == 0)
        return pixCopy(NULL, pixs);

    if ((pixt = pixBlocksum(pixs, pixacc, wc, hc)) == NULL)
        return (PIX *)ERROR_PTR("pixt not made", procName, NULL);

        
    thresh = (l_int32)(255. * rank);
    pixd = pixThresholdToBinary(pixt, thresh);
    pixInvert(pixd, pixd);
    pixDestroy(&pixt);
    return pixd;
}



PIX * pixBlocksum(PIX     *pixs, PIX     *pixacc, l_int32  wc, l_int32  hc)



{
l_int32    w, h, d, wplt, wpld;
l_uint32  *datat, *datad;
PIX       *pixt, *pixd;

    PROCNAME("pixBlocksum");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 1)
        return (PIX *)ERROR_PTR("pixs not 1 bpp", procName, NULL);
    if (wc < 0) wc = 0;
    if (hc < 0) hc = 0;
    if (w < 2 * wc + 1 || h < 2 * hc + 1) {
        wc = L_MIN(wc, (w - 1) / 2);
        hc = L_MIN(hc, (h - 1) / 2);
        L_WARNING("kernel too large; reducing!\n", procName);
        L_INFO("wc = %d, hc = %d\n", procName, wc, hc);
    }
    if (wc == 0 && hc == 0)
        return pixCopy(NULL, pixs);

    if (pixacc) {
        if (pixGetDepth(pixacc) != 32)
            return (PIX *)ERROR_PTR("pixacc not 32 bpp", procName, NULL);
        pixt = pixClone(pixacc);
    } else {
        if ((pixt = pixBlockconvAccum(pixs)) == NULL)
            return (PIX *)ERROR_PTR("pixt not made", procName, NULL);
    }

        
    if ((pixd = pixCreate(w, h, 8)) == NULL) {
        pixDestroy(&pixt);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }
    pixCopyResolution(pixd, pixs);

    wpld = pixGetWpl(pixd);
    wplt = pixGetWpl(pixt);
    datad = pixGetData(pixd);
    datat = pixGetData(pixt);
    blocksumLow(datad, w, h, wpld, datat, wplt, wc, hc);

    pixDestroy(&pixt);
    return pixd;
}



static void blocksumLow(l_uint32  *datad, l_int32    w, l_int32    h, l_int32    wpl, l_uint32  *dataa, l_int32    wpla, l_int32    wc, l_int32    hc)







{
l_int32    i, j, imax, imin, jmax, jmin;
l_int32    wn, hn, fwc, fhc, wmwc, hmhc;
l_float32  norm, normh, normw;
l_uint32   val;
l_uint32  *linemina, *linemaxa, *lined;

    PROCNAME("blocksumLow");

    wmwc = w - wc;
    hmhc = h - hc;
    if (wmwc <= 0 || hmhc <= 0) {
        L_ERROR("wc >= w || hc >=h\n", procName);
        return;
    }
    fwc = 2 * wc + 1;
    fhc = 2 * hc + 1;
    norm = 255. / ((l_float32)(fwc) * fhc);

        
    for (i = 0; i < h; i++) {
        imin = L_MAX(i - 1 - hc, 0);
        imax = L_MIN(i + hc, h - 1);
        lined = datad + wpl * i;
        linemina = dataa + wpla * imin;
        linemaxa = dataa + wpla * imax;
        for (j = 0; j < w; j++) {
            jmin = L_MAX(j - 1 - wc, 0);
            jmax = L_MIN(j + wc, w - 1);
            val = linemaxa[jmax] - linemaxa[jmin] - linemina[jmax] + linemina[jmin];
            val = (l_uint8)(norm * val);
            SET_DATA_BYTE(lined, j, val);
        }
    }

        
    for (i = 0; i <= hc; i++) {    
        hn = hc + i;
        normh = (l_float32)fhc / (l_float32)hn;   
        lined = datad + wpl * i;
        for (j = 0; j <= wc; j++) {
            wn = wc + j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normh * normw);
            SET_DATA_BYTE(lined, j, val);
        }
        for (j = wc + 1; j < wmwc; j++) {
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normh);
            SET_DATA_BYTE(lined, j, val);
        }
        for (j = wmwc; j < w; j++) {
            wn = wc + w - j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normh * normw);
            SET_DATA_BYTE(lined, j, val);
        }
    }

    for (i = hmhc; i < h; i++) {  
        hn = hc + h - i;
        normh = (l_float32)fhc / (l_float32)hn;   
        lined = datad + wpl * i;
        for (j = 0; j <= wc; j++) {
            wn = wc + j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normh * normw);
            SET_DATA_BYTE(lined, j, val);
        }
        for (j = wc + 1; j < wmwc; j++) {
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normh);
            SET_DATA_BYTE(lined, j, val);
        }
        for (j = wmwc; j < w; j++) {
            wn = wc + w - j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normh * normw);
            SET_DATA_BYTE(lined, j, val);
        }
    }

    for (i = hc + 1; i < hmhc; i++) {    
        lined = datad + wpl * i;
        for (j = 0; j <= wc; j++) {   
            wn = wc + j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normw);
            SET_DATA_BYTE(lined, j, val);
        }
        for (j = wmwc; j < w; j++) {   
            wn = wc + w - j;
            normw = (l_float32)fwc / (l_float32)wn;   
            val = GET_DATA_BYTE(lined, j);
            val = (l_uint8)(val * normw);
            SET_DATA_BYTE(lined, j, val);
        }
    }
}




PIX * pixCensusTransform(PIX     *pixs, l_int32  halfsize, PIX     *pixacc)


{
l_int32    i, j, w, h, wpls, wplv, wpld;
l_int32    vals, valv;
l_uint32  *datas, *datav, *datad, *lines, *linev, *lined;
PIX       *pixav, *pixd;

    PROCNAME("pixCensusTransform");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs not 8 bpp", procName, NULL);
    if (halfsize < 1)
        return (PIX *)ERROR_PTR("halfsize must be >= 1", procName, NULL);

        
    if ((pixav = pixBlockconvGray(pixs, pixacc, halfsize, halfsize))
          == NULL)
        return (PIX *)ERROR_PTR("pixav not made", procName, NULL);

        
    pixGetDimensions(pixs, &w, &h, NULL);
    if ((pixd = pixCreate(w, h, 1)) == NULL) {
        pixDestroy(&pixav);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }
    datas = pixGetData(pixs);
    datav = pixGetData(pixav);
    datad = pixGetData(pixd);
    wpls = pixGetWpl(pixs);
    wplv = pixGetWpl(pixav);
    wpld = pixGetWpl(pixd);
    for (i = 0; i < h; i++) {
        lines = datas + i * wpls;
        linev = datav + i * wplv;
        lined = datad + i * wpld;
        for (j = 0; j < w; j++) {
            vals = GET_DATA_BYTE(lines, j);
            valv = GET_DATA_BYTE(linev, j);
            if (vals > valv)
                SET_DATA_BIT(lined, j);
        }
    }

    pixDestroy(&pixav);
    return pixd;
}




PIX * pixConvolve(PIX       *pixs, L_KERNEL  *kel, l_int32    outdepth, l_int32    normflag)



{
l_int32    i, j, id, jd, k, m, w, h, d, wd, hd, sx, sy, cx, cy, wplt, wpld;
l_int32    val;
l_uint32  *datat, *datad, *linet, *lined;
l_float32  sum;
L_KERNEL  *keli, *keln;
PIX       *pixt, *pixd;

    PROCNAME("pixConvolve");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs has colormap", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8 && d != 16 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 8, 16, or 32 bpp", procName, NULL);
    if (!kel)
        return (PIX *)ERROR_PTR("kel not defined", procName, NULL);

    pixd = NULL;

    keli = kernelInvert(kel);
    kernelGetParameters(keli, &sy, &sx, &cy, &cx);
    if (normflag)
        keln = kernelNormalize(keli, 1.0);
    else keln = kernelCopy(keli);

    if ((pixt = pixAddMirroredBorder(pixs, cx, sx - cx, cy, sy - cy)) == NULL) {
        L_ERROR("pixt not made\n", procName);
        goto cleanup;
    }

    wd = (w + ConvolveSamplingFactX - 1) / ConvolveSamplingFactX;
    hd = (h + ConvolveSamplingFactY - 1) / ConvolveSamplingFactY;
    pixd = pixCreate(wd, hd, outdepth);
    datat = pixGetData(pixt);
    datad = pixGetData(pixd);
    wplt = pixGetWpl(pixt);
    wpld = pixGetWpl(pixd);
    for (i = 0, id = 0; id < hd; i += ConvolveSamplingFactY, id++) {
        lined = datad + id * wpld;
        for (j = 0, jd = 0; jd < wd; j += ConvolveSamplingFactX, jd++) {
            sum = 0.0;
            for (k = 0; k < sy; k++) {
                linet = datat + (i + k) * wplt;
                if (d == 8) {
                    for (m = 0; m < sx; m++) {
                        val = GET_DATA_BYTE(linet, j + m);
                        sum += val * keln->data[k][m];
                    }
                } else if (d == 16) {
                    for (m = 0; m < sx; m++) {
                        val = GET_DATA_TWO_BYTES(linet, j + m);
                        sum += val * keln->data[k][m];
                    }
                } else {  
                    for (m = 0; m < sx; m++) {
                        val = *(linet + j + m);
                        sum += val * keln->data[k][m];
                    }
                }
            }
            if (sum < 0.0) sum = -sum;  
            if (outdepth == 8)
                SET_DATA_BYTE(lined, jd, (l_int32)(sum + 0.5));
            else if (outdepth == 16)
                SET_DATA_TWO_BYTES(lined, jd, (l_int32)(sum + 0.5));
            else   *(lined + jd) = (l_uint32)(sum + 0.5);
        }
    }

cleanup:
    kernelDestroy(&keli);
    kernelDestroy(&keln);
    pixDestroy(&pixt);
    return pixd;
}



PIX * pixConvolveSep(PIX       *pixs, L_KERNEL  *kelx, L_KERNEL  *kely, l_int32    outdepth, l_int32    normflag)




{
l_int32    d, xfact, yfact;
L_KERNEL  *kelxn, *kelyn;
PIX       *pixt, *pixd;

    PROCNAME("pixConvolveSep");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    d = pixGetDepth(pixs);
    if (d != 8 && d != 16 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 8, 16, or 32 bpp", procName, NULL);
    if (!kelx)
        return (PIX *)ERROR_PTR("kelx not defined", procName, NULL);
    if (!kely)
        return (PIX *)ERROR_PTR("kely not defined", procName, NULL);

    xfact = ConvolveSamplingFactX;
    yfact = ConvolveSamplingFactY;
    if (normflag) {
        kelxn = kernelNormalize(kelx, 1000.0);
        kelyn = kernelNormalize(kely, 0.001);
        l_setConvolveSampling(xfact, 1);
        pixt = pixConvolve(pixs, kelxn, 32, 0);
        l_setConvolveSampling(1, yfact);
        pixd = pixConvolve(pixt, kelyn, outdepth, 0);
        l_setConvolveSampling(xfact, yfact);  
        kernelDestroy(&kelxn);
        kernelDestroy(&kelyn);
    } else {  
        l_setConvolveSampling(xfact, 1);
        pixt = pixConvolve(pixs, kelx, 32, 0);
        l_setConvolveSampling(1, yfact);
        pixd = pixConvolve(pixt, kely, outdepth, 0);
        l_setConvolveSampling(xfact, yfact);
    }

    pixDestroy(&pixt);
    return pixd;
}



PIX * pixConvolveRGB(PIX       *pixs, L_KERNEL  *kel)

{
PIX  *pixt, *pixr, *pixg, *pixb, *pixd;

    PROCNAME("pixConvolveRGB");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetDepth(pixs) != 32)
        return (PIX *)ERROR_PTR("pixs is not 32 bpp", procName, NULL);
    if (!kel)
        return (PIX *)ERROR_PTR("kel not defined", procName, NULL);

    pixt = pixGetRGBComponent(pixs, COLOR_RED);
    pixr = pixConvolve(pixt, kel, 8, 1);
    pixDestroy(&pixt);
    pixt = pixGetRGBComponent(pixs, COLOR_GREEN);
    pixg = pixConvolve(pixt, kel, 8, 1);
    pixDestroy(&pixt);
    pixt = pixGetRGBComponent(pixs, COLOR_BLUE);
    pixb = pixConvolve(pixt, kel, 8, 1);
    pixDestroy(&pixt);
    pixd = pixCreateRGBImage(pixr, pixg, pixb);

    pixDestroy(&pixr);
    pixDestroy(&pixg);
    pixDestroy(&pixb);
    return pixd;
}



PIX * pixConvolveRGBSep(PIX       *pixs, L_KERNEL  *kelx, L_KERNEL  *kely)


{
PIX  *pixt, *pixr, *pixg, *pixb, *pixd;

    PROCNAME("pixConvolveRGBSep");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetDepth(pixs) != 32)
        return (PIX *)ERROR_PTR("pixs is not 32 bpp", procName, NULL);
    if (!kelx || !kely)
        return (PIX *)ERROR_PTR("kelx, kely not both defined", procName, NULL);

    pixt = pixGetRGBComponent(pixs, COLOR_RED);
    pixr = pixConvolveSep(pixt, kelx, kely, 8, 1);
    pixDestroy(&pixt);
    pixt = pixGetRGBComponent(pixs, COLOR_GREEN);
    pixg = pixConvolveSep(pixt, kelx, kely, 8, 1);
    pixDestroy(&pixt);
    pixt = pixGetRGBComponent(pixs, COLOR_BLUE);
    pixb = pixConvolveSep(pixt, kelx, kely, 8, 1);
    pixDestroy(&pixt);
    pixd = pixCreateRGBImage(pixr, pixg, pixb);

    pixDestroy(&pixr);
    pixDestroy(&pixg);
    pixDestroy(&pixb);
    return pixd;
}




FPIX * fpixConvolve(FPIX      *fpixs, L_KERNEL  *kel, l_int32    normflag)


{
l_int32     i, j, id, jd, k, m, w, h, wd, hd, sx, sy, cx, cy, wplt, wpld;
l_float32   val;
l_float32  *datat, *datad, *linet, *lined;
l_float32   sum;
L_KERNEL   *keli, *keln;
FPIX       *fpixt, *fpixd;

    PROCNAME("fpixConvolve");

    if (!fpixs)
        return (FPIX *)ERROR_PTR("fpixs not defined", procName, NULL);
    if (!kel)
        return (FPIX *)ERROR_PTR("kel not defined", procName, NULL);

    fpixd = NULL;

    keli = kernelInvert(kel);
    kernelGetParameters(keli, &sy, &sx, &cy, &cx);
    if (normflag)
        keln = kernelNormalize(keli, 1.0);
    else keln = kernelCopy(keli);

    fpixGetDimensions(fpixs, &w, &h);
    fpixt = fpixAddMirroredBorder(fpixs, cx, sx - cx, cy, sy - cy);
    if (!fpixt) {
        L_ERROR("fpixt not made\n", procName);
        goto cleanup;
    }

    wd = (w + ConvolveSamplingFactX - 1) / ConvolveSamplingFactX;
    hd = (h + ConvolveSamplingFactY - 1) / ConvolveSamplingFactY;
    fpixd = fpixCreate(wd, hd);
    datat = fpixGetData(fpixt);
    datad = fpixGetData(fpixd);
    wplt = fpixGetWpl(fpixt);
    wpld = fpixGetWpl(fpixd);
    for (i = 0, id = 0; id < hd; i += ConvolveSamplingFactY, id++) {
        lined = datad + id * wpld;
        for (j = 0, jd = 0; jd < wd; j += ConvolveSamplingFactX, jd++) {
            sum = 0.0;
            for (k = 0; k < sy; k++) {
                linet = datat + (i + k) * wplt;
                for (m = 0; m < sx; m++) {
                    val = *(linet + j + m);
                    sum += val * keln->data[k][m];
                }
            }
            *(lined + jd) = sum;
        }
    }

cleanup:
    kernelDestroy(&keli);
    kernelDestroy(&keln);
    fpixDestroy(&fpixt);
    return fpixd;
}



FPIX * fpixConvolveSep(FPIX      *fpixs, L_KERNEL  *kelx, L_KERNEL  *kely, l_int32    normflag)



{
l_int32    xfact, yfact;
L_KERNEL  *kelxn, *kelyn;
FPIX      *fpixt, *fpixd;

    PROCNAME("fpixConvolveSep");

    if (!fpixs)
        return (FPIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (!kelx)
        return (FPIX *)ERROR_PTR("kelx not defined", procName, NULL);
    if (!kely)
        return (FPIX *)ERROR_PTR("kely not defined", procName, NULL);

    xfact = ConvolveSamplingFactX;
    yfact = ConvolveSamplingFactY;
    if (normflag) {
        kelxn = kernelNormalize(kelx, 1.0);
        kelyn = kernelNormalize(kely, 1.0);
        l_setConvolveSampling(xfact, 1);
        fpixt = fpixConvolve(fpixs, kelxn, 0);
        l_setConvolveSampling(1, yfact);
        fpixd = fpixConvolve(fpixt, kelyn, 0);
        l_setConvolveSampling(xfact, yfact);  
        kernelDestroy(&kelxn);
        kernelDestroy(&kelyn);
    } else {  
        l_setConvolveSampling(xfact, 1);
        fpixt = fpixConvolve(fpixs, kelx, 0);
        l_setConvolveSampling(1, yfact);
        fpixd = fpixConvolve(fpixt, kely, 0);
        l_setConvolveSampling(xfact, yfact);
    }

    fpixDestroy(&fpixt);
    return fpixd;
}




PIX * pixConvolveWithBias(PIX       *pixs, L_KERNEL  *kel1, L_KERNEL  *kel2, l_int32    force8, l_int32   *pbias)




{
l_int32    outdepth;
l_float32  min1, min2, min, minval, maxval, range;
FPIX      *fpix1, *fpix2;
PIX       *pixd;

    PROCNAME("pixConvolveWithBias");

    if (!pbias)
        return (PIX *)ERROR_PTR("&bias not defined", procName, NULL);
    *pbias = 0;
    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs has colormap", procName, NULL);
    if (!kel1)
        return (PIX *)ERROR_PTR("kel1 not defined", procName, NULL);

        
    kernelGetMinMax(kel1, &min1, NULL);
    min2 = 0.0;
    if (kel2)
        kernelGetMinMax(kel2, &min2, NULL);
    min = L_MIN(min1, min2);

    if (min >= 0.0) {
        if (!kel2)
            return pixConvolve(pixs, kel1, 8, 1);
        else return pixConvolveSep(pixs, kel1, kel2, 8, 1);
    }

        
    fpix1 = pixConvertToFPix(pixs, 1);
    if (!kel2)
        fpix2 = fpixConvolve(fpix1, kel1, 1);
    else fpix2 = fpixConvolveSep(fpix1, kel1, kel2, 1);
    fpixDestroy(&fpix1);

        
    fpixGetMin(fpix2, &minval, NULL, NULL);
    fpixGetMax(fpix2, &maxval, NULL, NULL);
    range = maxval - minval;
    *pbias = (minval < 0.0) ? -minval : 0.0;
    fpixAddMultConstant(fpix2, *pbias, 1.0);  
    if (range <= 255 || !force8) {  
        outdepth = (range > 255) ? 16 : 8;
    } else {  
        fpixAddMultConstant(fpix2, 0.0, (255.0 / range));
        outdepth = 8;
    }

        
    pixd = fpixConvertToPix(fpix2, outdepth, L_CLIP_TO_ZERO, 0);
    fpixDestroy(&fpix2);

    return pixd;
}




void l_setConvolveSampling(l_int32  xfact, l_int32  yfact)

{
    if (xfact < 1) xfact = 1;
    if (yfact < 1) yfact = 1;
    ConvolveSamplingFactX = xfact;
    ConvolveSamplingFactY = yfact;
}




PIX * pixAddGaussianNoise(PIX       *pixs, l_float32  stdev)

{
l_int32    i, j, w, h, d, wpls, wpld, val, rval, gval, bval;
l_uint32   pixel;
l_uint32  *datas, *datad, *lines, *lined;
PIX       *pixd;

    PROCNAME("pixAddGaussianNoise");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs has colormap", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 8 or 32 bpp", procName, NULL);

    pixd = pixCreateTemplateNoInit(pixs);
    datas = pixGetData(pixs);
    datad = pixGetData(pixd);
    wpls = pixGetWpl(pixs);
    wpld = pixGetWpl(pixd);
    for (i = 0; i < h; i++) {
        lines = datas + i * wpls;
        lined = datad + i * wpld;
        for (j = 0; j < w; j++) {
            if (d == 8) {
                val = GET_DATA_BYTE(lines, j);
                val += (l_int32)(stdev * gaussDistribSampling() + 0.5);
                val = L_MIN(255, L_MAX(0, val));
                SET_DATA_BYTE(lined, j, val);
            } else {  
                pixel = *(lines + j);
                extractRGBValues(pixel, &rval, &gval, &bval);
                rval += (l_int32)(stdev * gaussDistribSampling() + 0.5);
                rval = L_MIN(255, L_MAX(0, rval));
                gval += (l_int32)(stdev * gaussDistribSampling() + 0.5);
                gval = L_MIN(255, L_MAX(0, gval));
                bval += (l_int32)(stdev * gaussDistribSampling() + 0.5);
                bval = L_MIN(255, L_MAX(0, bval));
                composeRGBPixel(rval, gval, bval, lined + j);
            }
        }
    }
    return pixd;
}



l_float32 gaussDistribSampling(void)
{
static l_int32    select = 0;  
static l_float32  saveval;
l_float32         frand, xval, yval, rsq, factor;

    if (select == 0) {
        while (1) {  
            frand = (l_float32)rand() / (l_float32)RAND_MAX;
            xval = 2.0 * frand - 1.0;
            frand = (l_float32)rand() / (l_float32)RAND_MAX;
            yval = 2.0 * frand - 1.0;
            rsq = xval * xval + yval * yval;
            if (rsq > 0.0 && rsq < 1.0)  
                break;
        }
        factor = sqrt(-2.0 * log(rsq) / rsq);
        saveval = xval * factor;
        select = 1;
        return yval * factor;
    }
    else {
        select = 0;
        return saveval;
    }
}
