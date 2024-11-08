









    
static const l_int32  DefaultTileWidth = 10;    
static const l_int32  DefaultTileHeight = 15;   
static const l_int32  DefaultFgThreshold = 60;  
static const l_int32  DefaultMinCount = 40;     
static const l_int32  DefaultBgVal = 200;       
static const l_int32  DefaultXSmoothSize = 2;  
static const l_int32  DefaultYSmoothSize = 1;  

static l_int32 *iaaGetLinearTRC(l_int32 **iaa, l_int32 diff);







PIX * pixCleanBackgroundToWhite(PIX       *pixs, PIX       *pixim, PIX       *pixg, l_float32  gamma, l_int32    blackval, l_int32    whiteval)





{
l_int32  d;
PIX     *pixd;

    PROCNAME("pixCleanBackgroundToWhite");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    d = pixGetDepth(pixs);
    if (d != 8 && d != 32)
        return (PIX *)ERROR_PTR("depth not 8 or 32", procName, NULL);

    pixd = pixBackgroundNormSimple(pixs, pixim, pixg);
    if (!pixd)
        return (PIX *)ERROR_PTR("background norm failedd", procName, NULL);
    pixGammaTRC(pixd, pixd, gamma, blackval, whiteval);
    return pixd;
}




PIX * pixBackgroundNormSimple(PIX  *pixs, PIX  *pixim, PIX  *pixg)


{
    return pixBackgroundNorm(pixs, pixim, pixg, DefaultTileWidth, DefaultTileHeight, DefaultFgThreshold, DefaultMinCount, DefaultBgVal, DefaultXSmoothSize, DefaultYSmoothSize);



}



PIX * pixBackgroundNorm(PIX     *pixs, PIX     *pixim, PIX     *pixg, l_int32  sx, l_int32  sy, l_int32  thresh, l_int32  mincount, l_int32  bgval, l_int32  smoothx, l_int32  smoothy)









{
l_int32  d, allfg;
PIX     *pixm, *pixmi, *pixd;
PIX     *pixmr, *pixmg, *pixmb, *pixmri, *pixmgi, *pixmbi;

    PROCNAME("pixBackgroundNorm");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    d = pixGetDepth(pixs);
    if (d != 8 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 8 or 32 bpp", procName, NULL);
    if (sx < 4 || sy < 4)
        return (PIX *)ERROR_PTR("sx and sy must be >= 4", procName, NULL);
    if (mincount > sx * sy) {
        L_WARNING("mincount too large for tile size\n", procName);
        mincount = (sx * sy) / 3;
    }

        
    if (pixim) {
        pixInvert(pixim, pixim);
        pixZero(pixim, &allfg);
        pixInvert(pixim, pixim);
        if (allfg)
            return (PIX *)ERROR_PTR("pixim all foreground", procName, NULL);
    }

    pixd = NULL;
    if (d == 8) {
        pixm = NULL;
        pixGetBackgroundGrayMap(pixs, pixim, sx, sy, thresh, mincount, &pixm);
        if (!pixm) {
            L_WARNING("map not made; return a copy of the source\n", procName);
            return pixCopy(NULL, pixs);
        }

        pixmi = pixGetInvBackgroundMap(pixm, bgval, smoothx, smoothy);
        if (!pixmi) {
            L_WARNING("pixmi not made; return a copy of source\n", procName);
            pixDestroy(&pixm);
            return pixCopy(NULL, pixs);
        } else {
            pixd = pixApplyInvBackgroundGrayMap(pixs, pixmi, sx, sy);
        }

        pixDestroy(&pixm);
        pixDestroy(&pixmi);
    }
    else {
        pixmr = pixmg = pixmb = NULL;
        pixGetBackgroundRGBMap(pixs, pixim, pixg, sx, sy, thresh, mincount, &pixmr, &pixmg, &pixmb);
        if (!pixmr || !pixmg || !pixmb) {
            pixDestroy(&pixmr);
            pixDestroy(&pixmg);
            pixDestroy(&pixmb);
            L_WARNING("map not made; return a copy of the source\n", procName);
            return pixCopy(NULL, pixs);
        }

        pixmri = pixGetInvBackgroundMap(pixmr, bgval, smoothx, smoothy);
        pixmgi = pixGetInvBackgroundMap(pixmg, bgval, smoothx, smoothy);
        pixmbi = pixGetInvBackgroundMap(pixmb, bgval, smoothx, smoothy);
        if (!pixmri || !pixmgi || !pixmbi) {
            L_WARNING("not all pixm*i are made; return src copy\n", procName);
            pixd = pixCopy(NULL, pixs);
        } else {
            pixd = pixApplyInvBackgroundRGBMap(pixs, pixmri, pixmgi, pixmbi, sx, sy);
        }

        pixDestroy(&pixmr);
        pixDestroy(&pixmg);
        pixDestroy(&pixmb);
        pixDestroy(&pixmri);
        pixDestroy(&pixmgi);
        pixDestroy(&pixmbi);
    }

    if (!pixd)
        ERROR_PTR("pixd not made", procName, NULL);
    pixCopyResolution(pixd, pixs);
    return pixd;
}



PIX * pixBackgroundNormMorph(PIX     *pixs, PIX     *pixim, l_int32  reduction, l_int32  size, l_int32  bgval)




{
l_int32    d, allfg;
PIX       *pixm, *pixmi, *pixd;
PIX       *pixmr, *pixmg, *pixmb, *pixmri, *pixmgi, *pixmbi;

    PROCNAME("pixBackgroundNormMorph");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    d = pixGetDepth(pixs);
    if (d != 8 && d != 32)
        return (PIX *)ERROR_PTR("pixs not 8 or 32 bpp", procName, NULL);
    if (reduction < 2 || reduction > 16)
        return (PIX *)ERROR_PTR("reduction must be between 2 and 16", procName, NULL);

        
    if (pixim) {
        pixInvert(pixim, pixim);
        pixZero(pixim, &allfg);
        pixInvert(pixim, pixim);
        if (allfg)
            return (PIX *)ERROR_PTR("pixim all foreground", procName, NULL);
    }

    pixd = NULL;
    if (d == 8) {
        pixGetBackgroundGrayMapMorph(pixs, pixim, reduction, size, &pixm);
        if (!pixm)
            return (PIX *)ERROR_PTR("pixm not made", procName, NULL);
        pixmi = pixGetInvBackgroundMap(pixm, bgval, 0, 0);
        if (!pixmi)
            ERROR_PTR("pixmi not made", procName, NULL);
        else pixd = pixApplyInvBackgroundGrayMap(pixs, pixmi, reduction, reduction);

        pixDestroy(&pixm);
        pixDestroy(&pixmi);
    }
    else {  
        pixmr = pixmg = pixmb = NULL;
        pixGetBackgroundRGBMapMorph(pixs, pixim, reduction, size, &pixmr, &pixmg, &pixmb);
        if (!pixmr || !pixmg || !pixmb) {
            pixDestroy(&pixmr);
            pixDestroy(&pixmg);
            pixDestroy(&pixmb);
            return (PIX *)ERROR_PTR("not all pixm*", procName, NULL);
        }

        pixmri = pixGetInvBackgroundMap(pixmr, bgval, 0, 0);
        pixmgi = pixGetInvBackgroundMap(pixmg, bgval, 0, 0);
        pixmbi = pixGetInvBackgroundMap(pixmb, bgval, 0, 0);
        if (!pixmri || !pixmgi || !pixmbi)
            ERROR_PTR("not all pixm*i are made", procName, NULL);
        else pixd = pixApplyInvBackgroundRGBMap(pixs, pixmri, pixmgi, pixmbi, reduction, reduction);


        pixDestroy(&pixmr);
        pixDestroy(&pixmg);
        pixDestroy(&pixmb);
        pixDestroy(&pixmri);
        pixDestroy(&pixmgi);
        pixDestroy(&pixmbi);
    }

    if (!pixd)
        ERROR_PTR("pixd not made", procName, NULL);
    pixCopyResolution(pixd, pixs);
    return pixd;
}




l_ok pixBackgroundNormGrayArray(PIX     *pixs, PIX     *pixim, l_int32  sx, l_int32  sy, l_int32  thresh, l_int32  mincount, l_int32  bgval, l_int32  smoothx, l_int32  smoothy, PIX    **ppixd)









{
l_int32  allfg;
PIX     *pixm;

    PROCNAME("pixBackgroundNormGrayArray");

    if (!ppixd)
        return ERROR_INT("&pixd not defined", procName, 1);
    *ppixd = NULL;
    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not defined or not 8 bpp", procName, 1);
    if (pixGetColormap(pixs))
        return ERROR_INT("pixs is colormapped", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (sx < 4 || sy < 4)
        return ERROR_INT("sx and sy must be >= 4", procName, 1);
    if (mincount > sx * sy) {
        L_WARNING("mincount too large for tile size\n", procName);
        mincount = (sx * sy) / 3;
    }

        
    if (pixim) {
        pixInvert(pixim, pixim);
        pixZero(pixim, &allfg);
        pixInvert(pixim, pixim);
        if (allfg)
            return ERROR_INT("pixim all foreground", procName, 1);
    }

    pixGetBackgroundGrayMap(pixs, pixim, sx, sy, thresh, mincount, &pixm);
    if (!pixm)
        return ERROR_INT("pixm not made", procName, 1);
    *ppixd = pixGetInvBackgroundMap(pixm, bgval, smoothx, smoothy);
    pixCopyResolution(*ppixd, pixs);
    pixDestroy(&pixm);
    return 0;
}



l_ok pixBackgroundNormRGBArrays(PIX     *pixs, PIX     *pixim, PIX     *pixg, l_int32  sx, l_int32  sy, l_int32  thresh, l_int32  mincount, l_int32  bgval, l_int32  smoothx, l_int32  smoothy, PIX    **ppixr, PIX    **ppixg, PIX    **ppixb)












{
l_int32  allfg;
PIX     *pixmr, *pixmg, *pixmb;

    PROCNAME("pixBackgroundNormRGBArrays");

    if (!ppixr || !ppixg || !ppixb)
        return ERROR_INT("&pixr, &pixg, &pixb not all defined", procName, 1);
    *ppixr = *ppixg = *ppixb = NULL;
    if (!pixs)
        return ERROR_INT("pixs not defined", procName, 1);
    if (pixGetDepth(pixs) != 32)
        return ERROR_INT("pixs not 32 bpp", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (sx < 4 || sy < 4)
        return ERROR_INT("sx and sy must be >= 4", procName, 1);
    if (mincount > sx * sy) {
        L_WARNING("mincount too large for tile size\n", procName);
        mincount = (sx * sy) / 3;
    }

        
    if (pixim) {
        pixInvert(pixim, pixim);
        pixZero(pixim, &allfg);
        pixInvert(pixim, pixim);
        if (allfg)
            return ERROR_INT("pixim all foreground", procName, 1);
    }

    pixGetBackgroundRGBMap(pixs, pixim, pixg, sx, sy, thresh, mincount, &pixmr, &pixmg, &pixmb);
    if (!pixmr || !pixmg || !pixmb) {
        pixDestroy(&pixmr);
        pixDestroy(&pixmg);
        pixDestroy(&pixmb);
        return ERROR_INT("not all pixm* made", procName, 1);
    }

    *ppixr = pixGetInvBackgroundMap(pixmr, bgval, smoothx, smoothy);
    *ppixg = pixGetInvBackgroundMap(pixmg, bgval, smoothx, smoothy);
    *ppixb = pixGetInvBackgroundMap(pixmb, bgval, smoothx, smoothy);
    pixDestroy(&pixmr);
    pixDestroy(&pixmg);
    pixDestroy(&pixmb);
    return 0;
}



l_ok pixBackgroundNormGrayArrayMorph(PIX     *pixs, PIX     *pixim, l_int32  reduction, l_int32  size, l_int32  bgval, PIX    **ppixd)





{
l_int32  allfg;
PIX     *pixm;

    PROCNAME("pixBackgroundNormGrayArrayMorph");

    if (!ppixd)
        return ERROR_INT("&pixd not defined", procName, 1);
    *ppixd = NULL;
    if (!pixs)
        return ERROR_INT("pixs not defined", procName, 1);
    if (pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not 8 bpp", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (reduction < 2 || reduction > 16)
        return ERROR_INT("reduction must be between 2 and 16", procName, 1);

        
    if (pixim) {
        pixInvert(pixim, pixim);
        pixZero(pixim, &allfg);
        pixInvert(pixim, pixim);
        if (allfg)
            return ERROR_INT("pixim all foreground", procName, 1);
    }

    pixGetBackgroundGrayMapMorph(pixs, pixim, reduction, size, &pixm);
    if (!pixm)
        return ERROR_INT("pixm not made", procName, 1);
    *ppixd = pixGetInvBackgroundMap(pixm, bgval, 0, 0);
    pixCopyResolution(*ppixd, pixs);
    pixDestroy(&pixm);
    return 0;
}



l_ok pixBackgroundNormRGBArraysMorph(PIX     *pixs, PIX     *pixim, l_int32  reduction, l_int32  size, l_int32  bgval, PIX    **ppixr, PIX    **ppixg, PIX    **ppixb)







{
l_int32  allfg;
PIX     *pixmr, *pixmg, *pixmb;

    PROCNAME("pixBackgroundNormRGBArraysMorph");

    if (!ppixr || !ppixg || !ppixb)
        return ERROR_INT("&pixr, &pixg, &pixb not all defined", procName, 1);
    *ppixr = *ppixg = *ppixb = NULL;
    if (!pixs)
        return ERROR_INT("pixs not defined", procName, 1);
    if (pixGetDepth(pixs) != 32)
        return ERROR_INT("pixs not 32 bpp", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (reduction < 2 || reduction > 16)
        return ERROR_INT("reduction must be between 2 and 16", procName, 1);

        
    if (pixim) {
        pixInvert(pixim, pixim);
        pixZero(pixim, &allfg);
        pixInvert(pixim, pixim);
        if (allfg)
            return ERROR_INT("pixim all foreground", procName, 1);
    }

    pixGetBackgroundRGBMapMorph(pixs, pixim, reduction, size, &pixmr, &pixmg, &pixmb);
    if (!pixmr || !pixmg || !pixmb) {
        pixDestroy(&pixmr);
        pixDestroy(&pixmg);
        pixDestroy(&pixmb);
        return ERROR_INT("not all pixm* made", procName, 1);
    }

    *ppixr = pixGetInvBackgroundMap(pixmr, bgval, 0, 0);
    *ppixg = pixGetInvBackgroundMap(pixmg, bgval, 0, 0);
    *ppixb = pixGetInvBackgroundMap(pixmb, bgval, 0, 0);
    pixDestroy(&pixmr);
    pixDestroy(&pixmg);
    pixDestroy(&pixmb);
    return 0;
}




l_ok pixGetBackgroundGrayMap(PIX     *pixs, PIX     *pixim, l_int32  sx, l_int32  sy, l_int32  thresh, l_int32  mincount, PIX    **ppixd)






{
l_int32    w, h, wd, hd, wim, him, wpls, wplim, wpld, wplf;
l_int32    xim, yim, delx, nx, ny, i, j, k, m;
l_int32    count, sum, val8;
l_int32    empty, fgpixels;
l_uint32  *datas, *dataim, *datad, *dataf, *lines, *lineim, *lined, *linef;
l_float32  scalex, scaley;
PIX       *pixd, *piximi, *pixb, *pixf, *pixims;

    PROCNAME("pixGetBackgroundGrayMap");

    if (!ppixd)
        return ERROR_INT("&pixd not defined", procName, 1);
    *ppixd = NULL;
    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not defined or not 8 bpp", procName, 1);
    if (pixGetColormap(pixs))
        return ERROR_INT("pixs is colormapped", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (sx < 4 || sy < 4)
        return ERROR_INT("sx and sy must be >= 4", procName, 1);
    if (mincount > sx * sy) {
        L_WARNING("mincount too large for tile size\n", procName);
        mincount = (sx * sy) / 3;
    }

        
    fgpixels = 0;  
    if (pixim) {
        piximi = pixInvert(NULL, pixim);  
        pixZero(piximi, &empty);
        pixDestroy(&piximi);
        if (empty)
            return ERROR_INT("pixim all fg; no background", procName, 1);
        pixZero(pixim, &empty);
        if (!empty)  
            fgpixels = 1;
    }

        
    pixb = pixThresholdToBinary(pixs, thresh);
    pixf = pixMorphSequence(pixb, "d7.1 + d1.7", 0);
    pixDestroy(&pixb);


    
        
    w = pixGetWidth(pixs);
    h = pixGetHeight(pixs);
    wd = (w + sx - 1) / sx;
    hd = (h + sy - 1) / sy;
    pixd = pixCreate(wd, hd, 8);

        
    nx = w / sx;
    ny = h / sy;
    wpls = pixGetWpl(pixs);
    datas = pixGetData(pixs);
    wpld = pixGetWpl(pixd);
    datad = pixGetData(pixd);
    wplf = pixGetWpl(pixf);
    dataf = pixGetData(pixf);
    for (i = 0; i < ny; i++) {
        lines = datas + sy * i * wpls;
        linef = dataf + sy * i * wplf;
        lined = datad + i * wpld;
        for (j = 0; j < nx; j++) {
            delx = j * sx;
            sum = 0;
            count = 0;
            for (k = 0; k < sy; k++) {
                for (m = 0; m < sx; m++) {
                    if (GET_DATA_BIT(linef + k * wplf, delx + m) == 0) {
                        sum += GET_DATA_BYTE(lines + k * wpls, delx + m);
                        count++;
                    }
                }
            }
            if (count >= mincount) {
                val8 = sum / count;
                SET_DATA_BYTE(lined, j, val8);
            }
        }
    }
    pixDestroy(&pixf);

        
    pixims = NULL;
    if (pixim && fgpixels) {
        wim = pixGetWidth(pixim);
        him = pixGetHeight(pixim);
        dataim = pixGetData(pixim);
        wplim = pixGetWpl(pixim);
        for (i = 0; i < ny; i++) {
            yim = i * sy + sy / 2;
            if (yim >= him)
                break;
            lineim = dataim + yim * wplim;
            for (j = 0; j < nx; j++) {
                xim = j * sx + sx / 2;
                if (xim >= wim)
                    break;
                if (GET_DATA_BIT(lineim, xim))
                    pixSetPixel(pixd, j, i, 0);
            }
        }
    }

        
    if (pixFillMapHoles(pixd, nx, ny, L_FILL_BLACK)) {
        pixDestroy(&pixd);
        L_WARNING("can't make the map\n", procName);
        return 1;
    }

        
    if (pixim && fgpixels) {
        scalex = 1. / (l_float32)sx;
        scaley = 1. / (l_float32)sy;
        pixims = pixScaleBySampling(pixim, scalex, scaley);
        pixSmoothConnectedRegions(pixd, pixims, 2);
        pixDestroy(&pixims);
    }

    *ppixd = pixd;
    pixCopyResolution(*ppixd, pixs);
    return 0;
}



l_ok pixGetBackgroundRGBMap(PIX     *pixs, PIX     *pixim, PIX     *pixg, l_int32  sx, l_int32  sy, l_int32  thresh, l_int32  mincount, PIX    **ppixmr, PIX    **ppixmg, PIX    **ppixmb)









{
l_int32    w, h, wm, hm, wim, him, wpls, wplim, wplf;
l_int32    xim, yim, delx, nx, ny, i, j, k, m;
l_int32    count, rsum, gsum, bsum, rval, gval, bval;
l_int32    empty, fgpixels;
l_uint32   pixel;
l_uint32  *datas, *dataim, *dataf, *lines, *lineim, *linef;
l_float32  scalex, scaley;
PIX       *piximi, *pixgc, *pixb, *pixf, *pixims;
PIX       *pixmr, *pixmg, *pixmb;

    PROCNAME("pixGetBackgroundRGBMap");

    if (!ppixmr || !ppixmg || !ppixmb)
        return ERROR_INT("&pixm* not all defined", procName, 1);
    *ppixmr = *ppixmg = *ppixmb = NULL;
    if (!pixs)
        return ERROR_INT("pixs not defined", procName, 1);
    if (pixGetDepth(pixs) != 32)
        return ERROR_INT("pixs not 32 bpp", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (sx < 4 || sy < 4)
        return ERROR_INT("sx and sy must be >= 4", procName, 1);
    if (mincount > sx * sy) {
        L_WARNING("mincount too large for tile size\n", procName);
        mincount = (sx * sy) / 3;
    }

        
    fgpixels = 0;  
    if (pixim) {
        piximi = pixInvert(NULL, pixim);  
        pixZero(piximi, &empty);
        pixDestroy(&piximi);
        if (empty)
            return ERROR_INT("pixim all fg; no background", procName, 1);
        pixZero(pixim, &empty);
        if (!empty)  
            fgpixels = 1;
    }

        
    if (pixg)  
        pixgc = pixClone(pixg);
    else pixgc = pixConvertRGBToGrayFast(pixs);
    pixb = pixThresholdToBinary(pixgc, thresh);
    pixf = pixMorphSequence(pixb, "d7.1 + d1.7", 0);
    pixDestroy(&pixgc);
    pixDestroy(&pixb);

        
    w = pixGetWidth(pixs);
    h = pixGetHeight(pixs);
    wm = (w + sx - 1) / sx;
    hm = (h + sy - 1) / sy;
    pixmr = pixCreate(wm, hm, 8);
    pixmg = pixCreate(wm, hm, 8);
    pixmb = pixCreate(wm, hm, 8);

    
        
    nx = w / sx;
    ny = h / sy;
    wpls = pixGetWpl(pixs);
    datas = pixGetData(pixs);
    wplf = pixGetWpl(pixf);
    dataf = pixGetData(pixf);
    for (i = 0; i < ny; i++) {
        lines = datas + sy * i * wpls;
        linef = dataf + sy * i * wplf;
        for (j = 0; j < nx; j++) {
            delx = j * sx;
            rsum = gsum = bsum = 0;
            count = 0;
            for (k = 0; k < sy; k++) {
                for (m = 0; m < sx; m++) {
                    if (GET_DATA_BIT(linef + k * wplf, delx + m) == 0) {
                        pixel = *(lines + k * wpls + delx + m);
                        rsum += (pixel >> 24);
                        gsum += ((pixel >> 16) & 0xff);
                        bsum += ((pixel >> 8) & 0xff);
                        count++;
                    }
                }
            }
            if (count >= mincount) {
                rval = rsum / count;
                gval = gsum / count;
                bval = bsum / count;
                pixSetPixel(pixmr, j, i, rval);
                pixSetPixel(pixmg, j, i, gval);
                pixSetPixel(pixmb, j, i, bval);
            }
        }
    }
    pixDestroy(&pixf);

        
    if (pixim) {
        wim = pixGetWidth(pixim);
        him = pixGetHeight(pixim);
        dataim = pixGetData(pixim);
        wplim = pixGetWpl(pixim);
        for (i = 0; i < ny; i++) {
            yim = i * sy + sy / 2;
            if (yim >= him)
                break;
            lineim = dataim + yim * wplim;
            for (j = 0; j < nx; j++) {
                xim = j * sx + sx / 2;
                if (xim >= wim)
                    break;
                if (GET_DATA_BIT(lineim, xim)) {
                    pixSetPixel(pixmr, j, i, 0);
                    pixSetPixel(pixmg, j, i, 0);
                    pixSetPixel(pixmb, j, i, 0);
                }
            }
        }
    }

    
    if (pixFillMapHoles(pixmr, nx, ny, L_FILL_BLACK) || pixFillMapHoles(pixmg, nx, ny, L_FILL_BLACK) || pixFillMapHoles(pixmb, nx, ny, L_FILL_BLACK)) {

        pixDestroy(&pixmr);
        pixDestroy(&pixmg);
        pixDestroy(&pixmb);
        L_WARNING("can't make the maps\n", procName);
        return 1;
    }

        
    if (pixim && fgpixels) {
        scalex = 1. / (l_float32)sx;
        scaley = 1. / (l_float32)sy;
        pixims = pixScaleBySampling(pixim, scalex, scaley);
        pixSmoothConnectedRegions(pixmr, pixims, 2);
        pixSmoothConnectedRegions(pixmg, pixims, 2);
        pixSmoothConnectedRegions(pixmb, pixims, 2);
        pixDestroy(&pixims);
    }

    *ppixmr = pixmr;
    *ppixmg = pixmg;
    *ppixmb = pixmb;
    pixCopyResolution(*ppixmr, pixs);
    pixCopyResolution(*ppixmg, pixs);
    pixCopyResolution(*ppixmb, pixs);
    return 0;
}



l_ok pixGetBackgroundGrayMapMorph(PIX     *pixs, PIX     *pixim, l_int32  reduction, l_int32  size, PIX    **ppixm)




{
l_int32    nx, ny, empty, fgpixels;
l_float32  scale;
PIX       *pixm, *pix1, *pix2, *pix3, *pixims;

    PROCNAME("pixGetBackgroundGrayMapMorph");

    if (!ppixm)
        return ERROR_INT("&pixm not defined", procName, 1);
    *ppixm = NULL;
    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not defined or not 8 bpp", procName, 1);
    if (pixGetColormap(pixs))
        return ERROR_INT("pixs is colormapped", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);

        
    fgpixels = 0;  
    if (pixim) {
        pixInvert(pixim, pixim);  
        pixZero(pixim, &empty);
        if (empty)
            return ERROR_INT("pixim all fg; no background", procName, 1);
        pixInvert(pixim, pixim);  
        pixZero(pixim, &empty);
        if (!empty)  
            fgpixels = 1;
    }

        
    scale = 1. / (l_float32)reduction;
    pix1 = pixScaleBySampling(pixs, scale, scale);
    pix2 = pixCloseGray(pix1, size, size);
    pix3 = pixExtendByReplication(pix2, 1, 1);
    pixDestroy(&pix1);
    pixDestroy(&pix2);

        
    pixims = NULL;
    if (pixim) {
        pixims = pixScale(pixim, scale, scale);
        pixm = pixConvertTo8(pixims, FALSE);
        pixAnd(pixm, pixm, pix3);
    }
    else pixm = pixClone(pix3);
    pixDestroy(&pix3);

        
    nx = pixGetWidth(pixs) / reduction;
    ny = pixGetHeight(pixs) / reduction;
    if (pixFillMapHoles(pixm, nx, ny, L_FILL_BLACK)) {
        pixDestroy(&pixm);
        pixDestroy(&pixims);
        L_WARNING("can't make the map\n", procName);
        return 1;
    }

        
    if (pixim && fgpixels)
        pixSmoothConnectedRegions(pixm, pixims, 2);
    pixDestroy(&pixims);

    *ppixm = pixm;
    pixCopyResolution(*ppixm, pixs);
    return 0;
}



l_ok pixGetBackgroundRGBMapMorph(PIX     *pixs, PIX     *pixim, l_int32  reduction, l_int32  size, PIX    **ppixmr, PIX    **ppixmg, PIX    **ppixmb)






{
l_int32    nx, ny, empty, fgpixels;
l_float32  scale;
PIX       *pixm, *pixmr, *pixmg, *pixmb, *pix1, *pix2, *pix3, *pixims;

    PROCNAME("pixGetBackgroundRGBMapMorph");

    if (!ppixmr || !ppixmg || !ppixmb)
        return ERROR_INT("&pixm* not all defined", procName, 1);
    *ppixmr = *ppixmg = *ppixmb = NULL;
    if (!pixs)
        return ERROR_INT("pixs not defined", procName, 1);
    if (pixGetDepth(pixs) != 32)
        return ERROR_INT("pixs not 32 bpp", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);

        
    fgpixels = 0;  
    if (pixim) {
        pixInvert(pixim, pixim);  
        pixZero(pixim, &empty);
        if (empty)
            return ERROR_INT("pixim all fg; no background", procName, 1);
        pixInvert(pixim, pixim);  
        pixZero(pixim, &empty);
        if (!empty)  
            fgpixels = 1;
    }

        
    scale = 1. / (l_float32)reduction;
    pixims = NULL;
    pixm = NULL;
    if (pixim) {
        pixims = pixScale(pixim, scale, scale);
        pixm = pixConvertTo8(pixims, FALSE);
    }

        
    pix1 = pixScaleRGBToGrayFast(pixs, reduction, COLOR_RED);
    pix2 = pixCloseGray(pix1, size, size);
    pix3 = pixExtendByReplication(pix2, 1, 1);
    if (pixim)
        pixmr = pixAnd(NULL, pixm, pix3);
    else pixmr = pixClone(pix3);
    pixDestroy(&pix1);
    pixDestroy(&pix2);
    pixDestroy(&pix3);

    pix1 = pixScaleRGBToGrayFast(pixs, reduction, COLOR_GREEN);
    pix2 = pixCloseGray(pix1, size, size);
    pix3 = pixExtendByReplication(pix2, 1, 1);
    if (pixim)
        pixmg = pixAnd(NULL, pixm, pix3);
    else pixmg = pixClone(pix3);
    pixDestroy(&pix1);
    pixDestroy(&pix2);
    pixDestroy(&pix3);

    pix1 = pixScaleRGBToGrayFast(pixs, reduction, COLOR_BLUE);
    pix2 = pixCloseGray(pix1, size, size);
    pix3 = pixExtendByReplication(pix2, 1, 1);
    if (pixim)
        pixmb = pixAnd(NULL, pixm, pix3);
    else pixmb = pixClone(pix3);
    pixDestroy(&pixm);
    pixDestroy(&pix1);
    pixDestroy(&pix2);
    pixDestroy(&pix3);

        
    nx = pixGetWidth(pixs) / reduction;
    ny = pixGetHeight(pixs) / reduction;
    if (pixFillMapHoles(pixmr, nx, ny, L_FILL_BLACK) || pixFillMapHoles(pixmg, nx, ny, L_FILL_BLACK) || pixFillMapHoles(pixmb, nx, ny, L_FILL_BLACK)) {

        pixDestroy(&pixmr);
        pixDestroy(&pixmg);
        pixDestroy(&pixmb);
        pixDestroy(&pixims);
        L_WARNING("can't make the maps\n", procName);
        return 1;
    }

        
    if (pixim && fgpixels) {
        pixSmoothConnectedRegions(pixmr, pixims, 2);
        pixSmoothConnectedRegions(pixmg, pixims, 2);
        pixSmoothConnectedRegions(pixmb, pixims, 2);
        pixDestroy(&pixims);
    }

    *ppixmr = pixmr;
    *ppixmg = pixmg;
    *ppixmb = pixmb;
    pixCopyResolution(*ppixmr, pixs);
    pixCopyResolution(*ppixmg, pixs);
    pixCopyResolution(*ppixmb, pixs);
    return 0;
}



l_ok pixFillMapHoles(PIX     *pix, l_int32  nx, l_int32  ny, l_int32  filltype)



{
l_int32   w, h, y, nmiss, goodcol, i, j, found, ival, valtest;
l_uint32  val, lastval;
NUMA     *na;  
PIX      *pixt;

    PROCNAME("pixFillMapHoles");

    if (!pix || pixGetDepth(pix) != 8)
        return ERROR_INT("pix not defined or not 8 bpp", procName, 1);
    if (pixGetColormap(pix))
        return ERROR_INT("pix is colormapped", procName, 1);

    
    pixGetDimensions(pix, &w, &h, NULL);
    na = numaCreate(0);  
    nmiss = 0;
    valtest = (filltype == L_FILL_WHITE) ? 255 : 0;
    for (j = 0; j < nx; j++) {  
        found = FALSE;
        for (i = 0; i < ny; i++) {
            pixGetPixel(pix, j, i, &val);
            if (val != valtest) {
                y = i;
                found = TRUE;
                break;
            }
        }
        if (found == FALSE) {
            numaAddNumber(na, 0);  
            nmiss++;
        }
        else {
            numaAddNumber(na, 1);  
            for (i = y - 1; i >= 0; i--)  
                pixSetPixel(pix, j, i, val);
            pixGetPixel(pix, j, 0, &lastval);
            for (i = 1; i < h; i++) {  
                pixGetPixel(pix, j, i, &val);
                if (val == valtest)
                    pixSetPixel(pix, j, i, lastval);
                else lastval = val;
            }
        }
    }
    numaAddNumber(na, 0);  

    if (nmiss == nx) {  
        numaDestroy(&na);
        L_WARNING("no bg found; no data in any column\n", procName);
        return 1;
    }

    
    if (nmiss > 0) {  
        pixt = pixCopy(NULL, pix);
            
        goodcol = 0;
        for (j = 0; j < w; j++) {
            numaGetIValue(na, j, &ival);
            if (ival == 1) {
                goodcol = j;
                break;
            }
        }
        if (goodcol > 0) {  
            for (j = goodcol - 1; j >= 0; j--) {
                pixRasterop(pix, j, 0, 1, h, PIX_SRC, pixt, j + 1, 0);
                pixRasterop(pixt, j, 0, 1, h, PIX_SRC, pix, j, 0);
            }
        }
        for (j = goodcol + 1; j < w; j++) {   
            numaGetIValue(na, j, &ival);
            if (ival == 0) {
                    
                pixRasterop(pix, j, 0, 1, h, PIX_SRC, pixt, j - 1, 0);
                pixRasterop(pixt, j, 0, 1, h, PIX_SRC, pix, j, 0);
            }
        }
        pixDestroy(&pixt);
    }
    if (w > nx) {  
        for (i = 0; i < h; i++) {
            pixGetPixel(pix, w - 2, i, &val);
            pixSetPixel(pix, w - 1, i, val);
        }
    }

    numaDestroy(&na);
    return 0;
}



PIX * pixExtendByReplication(PIX     *pixs, l_int32  addw, l_int32  addh)


{
l_int32   w, h, i, j;
l_uint32  val;
PIX      *pixd;

    PROCNAME("pixExtendByReplication");

    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);

    if (addw == 0 && addh == 0)
        return pixCopy(NULL, pixs);

    pixGetDimensions(pixs, &w, &h, NULL);
    if ((pixd = pixCreate(w + addw, h + addh, 8)) == NULL)
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    pixRasterop(pixd, 0, 0, w, h, PIX_SRC, pixs, 0, 0);

    if (addw > 0) {
        for (i = 0; i < h; i++) {
            pixGetPixel(pixd, w - 1, i, &val);
            for (j = 0; j < addw; j++)
                pixSetPixel(pixd, w + j, i, val);
        }
    }

    if (addh > 0) {
        for (j = 0; j < w + addw; j++) {
            pixGetPixel(pixd, j, h - 1, &val);
            for (i = 0; i < addh; i++)
                pixSetPixel(pixd, j, h + i, val);
        }
    }

    pixCopyResolution(pixd, pixs);
    return pixd;
}



l_ok pixSmoothConnectedRegions(PIX     *pixs, PIX     *pixm, l_int32  factor)


{
l_int32    empty, i, n, x, y;
l_float32  aveval;
BOXA      *boxa;
PIX       *pixmc;
PIXA      *pixa;

    PROCNAME("pixSmoothConnectedRegions");

    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not defined or not 8 bpp", procName, 1);
    if (pixGetColormap(pixs))
        return ERROR_INT("pixs has colormap", procName, 1);
    if (!pixm) {
        L_INFO("pixm not defined\n", procName);
        return 0;
    }
    if (pixGetDepth(pixm) != 1)
        return ERROR_INT("pixm not 1 bpp", procName, 1);
    pixZero(pixm, &empty);
    if (empty) {
        L_INFO("pixm has no fg pixels; nothing to do\n", procName);
        return 0;
    }

    boxa = pixConnComp(pixm, &pixa, 8);
    n = boxaGetCount(boxa);
    for (i = 0; i < n; i++) {
        if ((pixmc = pixaGetPix(pixa, i, L_CLONE)) == NULL) {
            L_WARNING("missing pixmc!\n", procName);
            continue;
        }
        boxaGetBoxGeometry(boxa, i, &x, &y, NULL, NULL);
        pixGetAverageMasked(pixs, pixmc, x, y, factor, L_MEAN_ABSVAL, &aveval);
        pixPaintThroughMask(pixs, pixmc, x, y, (l_int32)aveval);
        pixDestroy(&pixmc);
    }

    boxaDestroy(&boxa);
    pixaDestroy(&pixa);
    return 0;
}






l_ok pixGetForegroundGrayMap(PIX     *pixs, PIX     *pixim, l_int32  sx, l_int32  sy, l_int32  thresh, PIX    **ppixd)





{
l_int32  w, h, d, wd, hd;
l_int32  empty, fgpixels;
PIX     *pixd, *piximi, *pixim2, *pixims, *pixs2, *pixb, *pixt1, *pixt2, *pixt3;

    PROCNAME("pixGetForegroundGrayMap");

    if (!ppixd)
        return ERROR_INT("&pixd not defined", procName, 1);
    *ppixd = NULL;
    if (!pixs)
        return ERROR_INT("pixs not defined", procName, 1);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8)
        return ERROR_INT("pixs not 8 bpp", procName, 1);
    if (pixim && pixGetDepth(pixim) != 1)
        return ERROR_INT("pixim not 1 bpp", procName, 1);
    if (sx < 2 || sy < 2)
        return ERROR_INT("sx and sy must be >= 2", procName, 1);

        
    wd = (w + sx - 1) / sx;
    hd = (h + sy - 1) / sy;
    pixd = pixCreate(wd, hd, 8);
    *ppixd = pixd;

        
    fgpixels = 0;  
    if (pixim) {
        piximi = pixInvert(NULL, pixim);  
        pixZero(piximi, &empty);
        pixDestroy(&piximi);
        if (empty)  
            return 0;
        pixZero(pixim, &empty);
        if (!empty)  
            fgpixels = 1;
    }

        
    pixs2 = pixScaleBySampling(pixs, 0.5, 0.5);
    if (pixim && fgpixels) {
        pixim2 = pixReduceBinary2(pixim, NULL);
        pixPaintThroughMask(pixs2, pixim2, 0, 0, 255);
        pixDestroy(&pixim2);
    }

        
    pixt1 = pixScaleGrayMinMax(pixs2, sx, sy, L_CHOOSE_MIN);



        
    pixb = pixThresholdToBinary(pixt1, thresh);  
    pixInvert(pixb, pixb);
    pixPaintThroughMask(pixt1, pixb, 0, 0, 255);
    pixDestroy(&pixb);

        
    pixt2 = pixExpandReplicate(pixt1, 2);



        
    pixFillMapHoles(pixt2, w / sx, h / sy, L_FILL_WHITE);



        
    pixt3 = pixBlockconv(pixt2, 8, 8);
    pixRasterop(pixd, 0, 0, wd, hd, PIX_SRC, pixt3, 0, 0);

        
    pixims = pixScaleBySampling(pixim, 1. / sx, 1. / sy);
    pixPaintThroughMask(pixd, pixims, 0, 0, 0);

    pixDestroy(&pixs2);
    pixDestroy(&pixt1);
    pixDestroy(&pixt2);
    pixDestroy(&pixt3);
    return 0;
}





PIX * pixGetInvBackgroundMap(PIX     *pixs, l_int32  bgval, l_int32  smoothx, l_int32  smoothy)



{
l_int32    w, h, wplsm, wpld, i, j;
l_int32    val, val16;
l_uint32  *datasm, *datad, *linesm, *lined;
PIX       *pixsm, *pixd;

    PROCNAME("pixGetInvBackgroundMap");

    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs has colormap", procName, NULL);
    pixGetDimensions(pixs, &w, &h, NULL);
    if (w < 5 || h < 5)
        return (PIX *)ERROR_PTR("w and h must be >= 5", procName, NULL);

        
    pixsm = pixBlockconv(pixs, smoothx, smoothy);
    datasm = pixGetData(pixsm);
    wplsm = pixGetWpl(pixsm);

        
    pixd = pixCreate(w, h, 16);
    datad = pixGetData(pixd);
    wpld = pixGetWpl(pixd);
    for (i = 0; i < h; i++) {
        linesm = datasm + i * wplsm;
        lined = datad + i * wpld;
        for (j = 0; j < w; j++) {
            val = GET_DATA_BYTE(linesm, j);
            if (val > 0)
                val16 = (256 * bgval) / val;
            else {  
                L_WARNING("smoothed bg has 0 pixel!\n", procName);
                val16 = bgval / 2;
            }
            SET_DATA_TWO_BYTES(lined, j, val16);
        }
    }

    pixDestroy(&pixsm);
    pixCopyResolution(pixd, pixs);
    return pixd;
}




PIX * pixApplyInvBackgroundGrayMap(PIX     *pixs, PIX     *pixm, l_int32  sx, l_int32  sy)



{
l_int32    w, h, wm, hm, wpls, wpld, i, j, k, m, xoff, yoff;
l_int32    vals, vald;
l_uint32   val16;
l_uint32  *datas, *datad, *lines, *lined, *flines, *flined;
PIX       *pixd;

    PROCNAME("pixApplyInvBackgroundGrayMap");

    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs has colormap", procName, NULL);
    if (!pixm || pixGetDepth(pixm) != 16)
        return (PIX *)ERROR_PTR("pixm undefined or not 16 bpp", procName, NULL);
    if (sx == 0 || sy == 0)
        return (PIX *)ERROR_PTR("invalid sx and/or sy", procName, NULL);

    datas = pixGetData(pixs);
    wpls = pixGetWpl(pixs);
    pixGetDimensions(pixs, &w, &h, NULL);
    pixGetDimensions(pixm, &wm, &hm, NULL);
    if ((pixd = pixCreateTemplate(pixs)) == NULL)
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    datad = pixGetData(pixd);
    wpld = pixGetWpl(pixd);
    for (i = 0; i < hm; i++) {
        lines = datas + sy * i * wpls;
        lined = datad + sy * i * wpld;
        yoff = sy * i;
        for (j = 0; j < wm; j++) {
            pixGetPixel(pixm, j, i, &val16);
            xoff = sx * j;
            for (k = 0; k < sy && yoff + k < h; k++) {
                flines = lines + k * wpls;
                flined = lined + k * wpld;
                for (m = 0; m < sx && xoff + m < w; m++) {
                    vals = GET_DATA_BYTE(flines, xoff + m);
                    vald = (vals * val16) / 256;
                    vald = L_MIN(vald, 255);
                    SET_DATA_BYTE(flined, xoff + m, vald);
                }
            }
        }
    }

    return pixd;
}



PIX * pixApplyInvBackgroundRGBMap(PIX     *pixs, PIX     *pixmr, PIX     *pixmg, PIX     *pixmb, l_int32  sx, l_int32  sy)





{
l_int32    w, h, wm, hm, wpls, wpld, i, j, k, m, xoff, yoff;
l_int32    rvald, gvald, bvald;
l_uint32   vals;
l_uint32   rval16, gval16, bval16;
l_uint32  *datas, *datad, *lines, *lined, *flines, *flined;
PIX       *pixd;

    PROCNAME("pixApplyInvBackgroundRGBMap");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetDepth(pixs) != 32)
        return (PIX *)ERROR_PTR("pixs not 32 bpp", procName, NULL);
    if (!pixmr || !pixmg || !pixmb)
        return (PIX *)ERROR_PTR("pix maps not all defined", procName, NULL);
    if (pixGetDepth(pixmr) != 16 || pixGetDepth(pixmg) != 16 || pixGetDepth(pixmb) != 16)
        return (PIX *)ERROR_PTR("pix maps not all 16 bpp", procName, NULL);
    if (sx == 0 || sy == 0)
        return (PIX *)ERROR_PTR("invalid sx and/or sy", procName, NULL);

    datas = pixGetData(pixs);
    wpls = pixGetWpl(pixs);
    w = pixGetWidth(pixs);
    h = pixGetHeight(pixs);
    wm = pixGetWidth(pixmr);
    hm = pixGetHeight(pixmr);
    if ((pixd = pixCreateTemplate(pixs)) == NULL)
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    datad = pixGetData(pixd);
    wpld = pixGetWpl(pixd);
    for (i = 0; i < hm; i++) {
        lines = datas + sy * i * wpls;
        lined = datad + sy * i * wpld;
        yoff = sy * i;
        for (j = 0; j < wm; j++) {
            pixGetPixel(pixmr, j, i, &rval16);
            pixGetPixel(pixmg, j, i, &gval16);
            pixGetPixel(pixmb, j, i, &bval16);
            xoff = sx * j;
            for (k = 0; k < sy && yoff + k < h; k++) {
                flines = lines + k * wpls;
                flined = lined + k * wpld;
                for (m = 0; m < sx && xoff + m < w; m++) {
                    vals = *(flines + xoff + m);
                    rvald = ((vals >> 24) * rval16) / 256;
                    rvald = L_MIN(rvald, 255);
                    gvald = (((vals >> 16) & 0xff) * gval16) / 256;
                    gvald = L_MIN(gvald, 255);
                    bvald = (((vals >> 8) & 0xff) * bval16) / 256;
                    bvald = L_MIN(bvald, 255);
                    composeRGBPixel(rvald, gvald, bvald, flined + xoff + m);
                }
            }
        }
    }

    return pixd;
}




PIX * pixApplyVariableGrayMap(PIX     *pixs, PIX     *pixg, l_int32  target)


{
l_int32    i, j, w, h, d, wpls, wplg, wpld, vals, valg, vald;
l_uint8   *lut;
l_uint32  *datas, *datag, *datad, *lines, *lineg, *lined;
l_float32  fval;
PIX       *pixd;

    PROCNAME("pixApplyVariableGrayMap");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (!pixg)
        return (PIX *)ERROR_PTR("pixg not defined", procName, NULL);
    if (!pixSizesEqual(pixs, pixg))
        return (PIX *)ERROR_PTR("pix sizes not equal", procName, NULL);
    pixGetDimensions(pixs, &w, &h, &d);
    if (d != 8)
        return (PIX *)ERROR_PTR("depth not 8 bpp", procName, NULL);

        
    lut = NULL;
    if (w * h > 100000) {  
        if ((lut = (l_uint8 *)LEPT_CALLOC(0x10000, sizeof(l_uint8))) == NULL)
            return (PIX *)ERROR_PTR("lut not made", procName, NULL);
        for (i = 0; i < 256; i++) {
            for (j = 0; j < 256; j++) {
                fval = (l_float32)(i * target) / (j + 0.5);
                lut[(i << 8) + j] = L_MIN(255, (l_int32)(fval + 0.5));
            }
        }
    }

    if ((pixd = pixCreateNoInit(w, h, 8)) == NULL) {
        LEPT_FREE(lut);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }
    pixCopyResolution(pixd, pixs);
    datad = pixGetData(pixd);
    wpld = pixGetWpl(pixd);
    datas = pixGetData(pixs);
    wpls = pixGetWpl(pixs);
    datag = pixGetData(pixg);
    wplg = pixGetWpl(pixg);
    for (i = 0; i < h; i++) {
        lines = datas + i * wpls;
        lineg = datag + i * wplg;
        lined = datad + i * wpld;
        if (lut) {
            for (j = 0; j < w; j++) {
                vals = GET_DATA_BYTE(lines, j);
                valg = GET_DATA_BYTE(lineg, j);
                vald = lut[(vals << 8) + valg];
                SET_DATA_BYTE(lined, j, vald);
            }
        }
        else {
            for (j = 0; j < w; j++) {
                vals = GET_DATA_BYTE(lines, j);
                valg = GET_DATA_BYTE(lineg, j);
                fval = (l_float32)(vals * target) / (valg + 0.5);
                vald = L_MIN(255, (l_int32)(fval + 0.5));
                SET_DATA_BYTE(lined, j, vald);
            }
        }
    }

    LEPT_FREE(lut);
    return pixd;
}




PIX * pixGlobalNormRGB(PIX     *pixd, PIX     *pixs, l_int32  rval, l_int32  gval, l_int32  bval, l_int32  mapval)





{
l_int32    w, h, d, i, j, ncolors, rv, gv, bv, wpl;
l_int32   *rarray, *garray, *barray;
l_uint32  *data, *line;
NUMA      *nar, *nag, *nab;
PIXCMAP   *cmap;

    PROCNAME("pixGlobalNormRGB");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    cmap = pixGetColormap(pixs);
    pixGetDimensions(pixs, &w, &h, &d);
    if (!cmap && d != 32)
        return (PIX *)ERROR_PTR("pixs not cmapped or 32 bpp", procName, NULL);
    if (mapval <= 0) {
        L_WARNING("mapval must be > 0; setting to 255\n", procName);
        mapval = 255;
    }

        
    if ((pixd = pixCopy(pixd, pixs)) == NULL)
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);

        
    nar = numaGammaTRC(1.0, 0, L_MAX(1, 255 * rval / mapval));
    nag = numaGammaTRC(1.0, 0, L_MAX(1, 255 * gval / mapval));
    nab = numaGammaTRC(1.0, 0, L_MAX(1, 255 * bval / mapval));

        
    rarray = numaGetIArray(nar);
    garray = numaGetIArray(nag);
    barray = numaGetIArray(nab);
    if (!nar || !nag || !nab || !rarray || !garray || !barray) {
        L_ERROR("allocation failure in arrays\n", procName);
        goto cleanup_arrays;
    }

    if (cmap) {
        ncolors = pixcmapGetCount(cmap);
        for (i = 0; i < ncolors; i++) {
            pixcmapGetColor(cmap, i, &rv, &gv, &bv);
            pixcmapResetColor(cmap, i, rarray[rv], garray[gv], barray[bv]);
        }
    }
    else {
        data = pixGetData(pixd);
        wpl = pixGetWpl(pixd);
        for (i = 0; i < h; i++) {
            line = data + i * wpl;
            for (j = 0; j < w; j++) {
                extractRGBValues(line[j], &rv, &gv, &bv);
                composeRGBPixel(rarray[rv], garray[gv], barray[bv], line + j);
            }
        }
    }

cleanup_arrays:
    numaDestroy(&nar);
    numaDestroy(&nag);
    numaDestroy(&nab);
    LEPT_FREE(rarray);
    LEPT_FREE(garray);
    LEPT_FREE(barray);
    return pixd;
}



PIX * pixGlobalNormNoSatRGB(PIX       *pixd, PIX       *pixs, l_int32    rval, l_int32    gval, l_int32    bval, l_int32    factor, l_float32  rank)






{
l_int32    mapval;
l_float32  rankrval, rankgval, rankbval;
l_float32  rfract, gfract, bfract, maxfract;

    PROCNAME("pixGlobalNormNoSatRGB");

    if (!pixs)
        return (PIX *)ERROR_PTR("pixs not defined", procName, NULL);
    if (pixGetDepth(pixs) != 32)
        return (PIX *)ERROR_PTR("pixs not 32 bpp", procName, NULL);
    if (factor < 1)
        return (PIX *)ERROR_PTR("sampling factor < 1", procName, NULL);
    if (rank < 0.0 || rank > 1.0)
        return (PIX *)ERROR_PTR("rank not in [0.0 ... 1.0]", procName, NULL);
    if (rval <= 0 || gval <= 0 || bval <= 0)
        return (PIX *)ERROR_PTR("invalid estim. color values", procName, NULL);

        
    pixGetRankValueMaskedRGB(pixs, NULL, 0, 0, factor, rank, &rankrval, &rankgval, &rankbval);
    rfract = rankrval / (l_float32)rval;
    gfract = rankgval / (l_float32)gval;
    bfract = rankbval / (l_float32)bval;
    maxfract = L_MAX(rfract, gfract);
    maxfract = L_MAX(maxfract, bfract);

    lept_stderr("rankrval = %7.2f, rankgval = %7.2f, rankbval = %7.2f\n", rankrval, rankgval, rankbval);
    lept_stderr("rfract = %7.4f, gfract = %7.4f, bfract = %7.4f\n", rfract, gfract, bfract);


    mapval = (l_int32)(255. / maxfract);
    pixd = pixGlobalNormRGB(pixd, pixs, rval, gval, bval, mapval);
    return pixd;
}




l_ok pixThresholdSpreadNorm(PIX       *pixs, l_int32    filtertype, l_int32    edgethresh, l_int32    smoothx, l_int32    smoothy, l_float32  gamma, l_int32    minval, l_int32    maxval, l_int32    targetthresh, PIX      **ppixth, PIX      **ppixb, PIX      **ppixd)











{
PIX  *pixe, *pixet, *pixsd, *pixg1, *pixg2, *pixth;

    PROCNAME("pixThresholdSpreadNorm");

    if (ppixth) *ppixth = NULL;
    if (ppixb) *ppixb = NULL;
    if (ppixd) *ppixd = NULL;
    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs not defined or not 8 bpp", procName, 1);
    if (pixGetColormap(pixs))
        return ERROR_INT("pixs is colormapped", procName, 1);
    if (!ppixth && !ppixb && !ppixd)
        return ERROR_INT("no output requested", procName, 1);
    if (filtertype != L_SOBEL_EDGE && filtertype != L_TWO_SIDED_EDGE)
        return ERROR_INT("invalid filter type", procName, 1);

        
    if (filtertype == L_SOBEL_EDGE)
        pixe = pixSobelEdgeFilter(pixs, L_VERTICAL_EDGES);
    else   pixe = pixTwoSidedEdgeFilter(pixs, L_VERTICAL_EDGES);
    pixet = pixThresholdToBinary(pixe, edgethresh);
    pixInvert(pixet, pixet);

        
    pixsd = pixCreateTemplate(pixs);
    pixCombineMasked(pixsd, pixs, pixet);

        
    pixg1 = pixSeedspread(pixsd, 4);
    pixg2 = pixBlockconv(pixg1, smoothx, smoothy);

        
    pixth = pixGammaTRC(NULL, pixg2, gamma, minval, maxval);

        
    if (ppixd) {
        *ppixd = pixApplyVariableGrayMap(pixs, pixth, targetthresh);
        if (ppixb)
            *ppixb = pixThresholdToBinary(*ppixd, targetthresh);
    }
    else if (ppixb)
        *ppixb = pixVarThresholdToBinary(pixs, pixth);

    if (ppixth)
        *ppixth = pixth;
    else pixDestroy(&pixth);

    pixDestroy(&pixe);
    pixDestroy(&pixet);
    pixDestroy(&pixsd);
    pixDestroy(&pixg1);
    pixDestroy(&pixg2);
    return 0;
}




PIX * pixBackgroundNormFlex(PIX     *pixs, l_int32  sx, l_int32  sy, l_int32  smoothx, l_int32  smoothy, l_int32  delta)





{
l_float32  scalex, scaley;
PIX       *pixt, *pixsd, *pixmin, *pixbg, *pixbgi, *pixd;

    PROCNAME("pixBackgroundNormFlex");

    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, NULL);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs is colormapped", procName, NULL);
    if (sx < 3 || sy < 3)
        return (PIX *)ERROR_PTR("sx and/or sy less than 3", procName, NULL);
    if (sx > 10 || sy > 10)
        return (PIX *)ERROR_PTR("sx and/or sy exceed 10", procName, NULL);
    if (smoothx < 1 || smoothy < 1)
        return (PIX *)ERROR_PTR("smooth params less than 1", procName, NULL);
    if (smoothx > 3 || smoothy > 3)
        return (PIX *)ERROR_PTR("smooth params exceed 3", procName, NULL);

        
    scalex = 1. / (l_float32)sx;
    scaley = 1. / (l_float32)sy;
    pixt = pixScaleSmooth(pixs, scalex, scaley);

        
    if (delta <= 0)
        pixsd = pixClone(pixt);
    else {
        pixLocalExtrema(pixt, 0, 0, &pixmin, NULL);
        pixsd = pixSeedfillGrayBasin(pixmin, pixt, delta, 4);
        pixDestroy(&pixmin);
    }
    pixbg = pixExtendByReplication(pixsd, 1, 1);

        
    pixbgi = pixGetInvBackgroundMap(pixbg, 200, smoothx, smoothy);
    pixd = pixApplyInvBackgroundGrayMap(pixs, pixbgi, sx, sy);

    pixDestroy(&pixt);
    pixDestroy(&pixsd);
    pixDestroy(&pixbg);
    pixDestroy(&pixbgi);
    return pixd;
}




PIX * pixContrastNorm(PIX       *pixd, PIX       *pixs, l_int32    sx, l_int32    sy, l_int32    mindiff, l_int32    smoothx, l_int32    smoothy)






{
PIX  *pixmin, *pixmax;

    PROCNAME("pixContrastNorm");

    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, pixd);
    if (pixd && pixd != pixs)
        return (PIX *)ERROR_PTR("pixd not null or == pixs", procName, pixd);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs is colormapped", procName, pixd);
    if (sx < 5 || sy < 5)
        return (PIX *)ERROR_PTR("sx and/or sy less than 5", procName, pixd);
    if (smoothx < 0 || smoothy < 0)
        return (PIX *)ERROR_PTR("smooth params less than 0", procName, pixd);
    if (smoothx > 8 || smoothy > 8)
        return (PIX *)ERROR_PTR("smooth params exceed 8", procName, pixd);

        
    pixMinMaxTiles(pixs, sx, sy, mindiff, smoothx, smoothy, &pixmin, &pixmax);

        
    pixd = pixLinearTRCTiled(pixd, pixs, sx, sy, pixmin, pixmax);

    pixDestroy(&pixmin);
    pixDestroy(&pixmax);
    return pixd;
}



l_ok pixMinMaxTiles(PIX     *pixs, l_int32  sx, l_int32  sy, l_int32  mindiff, l_int32  smoothx, l_int32  smoothy, PIX    **ppixmin, PIX    **ppixmax)







{
l_int32  w, h;
PIX     *pixmin1, *pixmax1, *pixmin2, *pixmax2;

    PROCNAME("pixMinMaxTiles");

    if (ppixmin) *ppixmin = NULL;
    if (ppixmax) *ppixmax = NULL;
    if (!ppixmin || !ppixmax)
        return ERROR_INT("&pixmin or &pixmax undefined", procName, 1);
    if (!pixs || pixGetDepth(pixs) != 8)
        return ERROR_INT("pixs undefined or not 8 bpp", procName, 1);
    if (pixGetColormap(pixs))
        return ERROR_INT("pixs is colormapped", procName, 1);
    if (sx < 5 || sy < 5)
        return ERROR_INT("sx and/or sy less than 3", procName, 1);
    if (smoothx < 0 || smoothy < 0)
        return ERROR_INT("smooth params less than 0", procName, 1);
    if (smoothx > 5 || smoothy > 5)
        return ERROR_INT("smooth params exceed 5", procName, 1);

        
    pixmin1 = pixScaleGrayMinMax(pixs, sx, sy, L_CHOOSE_MIN);
    pixmax1 = pixScaleGrayMinMax(pixs, sx, sy, L_CHOOSE_MAX);

    pixmin2 = pixExtendByReplication(pixmin1, 1, 1);
    pixmax2 = pixExtendByReplication(pixmax1, 1, 1);
    pixDestroy(&pixmin1);
    pixDestroy(&pixmax1);

        
    pixAddConstantGray(pixmin2, 1);
    pixAddConstantGray(pixmax2, 1);

        
    pixSetLowContrast(pixmin2, pixmax2, mindiff);

        
    pixGetDimensions(pixmin2, &w, &h, NULL);
    pixFillMapHoles(pixmin2, w, h, L_FILL_BLACK);
    pixFillMapHoles(pixmax2, w, h, L_FILL_BLACK);

        
    if (smoothx > 0 || smoothy > 0) {
        smoothx = L_MIN(smoothx, (w - 1) / 2);
        smoothy = L_MIN(smoothy, (h - 1) / 2);
        *ppixmin = pixBlockconv(pixmin2, smoothx, smoothy);
        *ppixmax = pixBlockconv(pixmax2, smoothx, smoothy);
    }
    else {
        *ppixmin = pixClone(pixmin2);
        *ppixmax = pixClone(pixmax2);
    }
    pixCopyResolution(*ppixmin, pixs);
    pixCopyResolution(*ppixmax, pixs);
    pixDestroy(&pixmin2);
    pixDestroy(&pixmax2);

    return 0;
}



l_ok pixSetLowContrast(PIX     *pixs1, PIX     *pixs2, l_int32  mindiff)


{
l_int32    i, j, w, h, d, wpl, val1, val2, found;
l_uint32  *data1, *data2, *line1, *line2;

    PROCNAME("pixSetLowContrast");

    if (!pixs1 || !pixs2)
        return ERROR_INT("pixs1 and pixs2 not both defined", procName, 1);
    if (pixSizesEqual(pixs1, pixs2) == 0)
        return ERROR_INT("pixs1 and pixs2 not equal size", procName, 1);
    pixGetDimensions(pixs1, &w, &h, &d);
    if (d != 8)
        return ERROR_INT("depth not 8 bpp", procName, 1);
    if (mindiff > 254) return 0;

    data1 = pixGetData(pixs1);
    data2 = pixGetData(pixs2);
    wpl = pixGetWpl(pixs1);
    found = 0;  
    for (i = 0; i < h; i++) {
        line1 = data1 + i * wpl;
        line2 = data2 + i * wpl;
        for (j = 0; j < w; j++) {
            val1 = GET_DATA_BYTE(line1, j);
            val2 = GET_DATA_BYTE(line2, j);
            if (L_ABS(val1 - val2) >= mindiff) {
                found = 1;
                break;
            }
        }
        if (found) break;
    }
    if (!found) {
        L_WARNING("no pixel pair diffs as large as mindiff\n", procName);
        pixClearAll(pixs1);
        pixClearAll(pixs2);
        return 1;
    }

    for (i = 0; i < h; i++) {
        line1 = data1 + i * wpl;
        line2 = data2 + i * wpl;
        for (j = 0; j < w; j++) {
            val1 = GET_DATA_BYTE(line1, j);
            val2 = GET_DATA_BYTE(line2, j);
            if (L_ABS(val1 - val2) < mindiff) {
                SET_DATA_BYTE(line1, j, 0);
                SET_DATA_BYTE(line2, j, 0);
            }
        }
    }

    return 0;
}



PIX * pixLinearTRCTiled(PIX       *pixd, PIX       *pixs, l_int32    sx, l_int32    sy, PIX       *pixmin, PIX       *pixmax)





{
l_int32    i, j, k, m, w, h, wt, ht, wpl, wplt, xoff, yoff;
l_int32    minval, maxval, val, sval;
l_int32   *ia;
l_int32  **iaa;
l_uint32  *data, *datamin, *datamax, *line, *tline, *linemin, *linemax;

    PROCNAME("pixLinearTRCTiled");

    if (!pixs || pixGetDepth(pixs) != 8)
        return (PIX *)ERROR_PTR("pixs undefined or not 8 bpp", procName, pixd);
    if (pixd && pixd != pixs)
        return (PIX *)ERROR_PTR("pixd not null or == pixs", procName, pixd);
    if (pixGetColormap(pixs))
        return (PIX *)ERROR_PTR("pixs is colormapped", procName, pixd);
    if (!pixmin || !pixmax)
        return (PIX *)ERROR_PTR("pixmin & pixmax not defined", procName, pixd);
    if (sx < 5 || sy < 5)
        return (PIX *)ERROR_PTR("sx and/or sy less than 5", procName, pixd);

    if ((iaa = (l_int32 **)LEPT_CALLOC(256, sizeof(l_int32 *))) == NULL)
        return (PIX *)ERROR_PTR("iaa not made", procName, NULL);
    if ((pixd = pixCopy(pixd, pixs)) == NULL) {
        LEPT_FREE(iaa);
        return (PIX *)ERROR_PTR("pixd not made", procName, NULL);
    }
    pixGetDimensions(pixd, &w, &h, NULL);

    data = pixGetData(pixd);
    wpl = pixGetWpl(pixd);
    datamin = pixGetData(pixmin);
    datamax = pixGetData(pixmax);
    wplt = pixGetWpl(pixmin);
    pixGetDimensions(pixmin, &wt, &ht, NULL);
    for (i = 0; i < ht; i++) {
        line = data + sy * i * wpl;
        linemin = datamin + i * wplt;
        linemax = datamax + i * wplt;
        yoff = sy * i;
        for (j = 0; j < wt; j++) {
            xoff = sx * j;
            minval = GET_DATA_BYTE(linemin, j);
            maxval = GET_DATA_BYTE(linemax, j);
            if (maxval == minval) {
                L_ERROR("shouldn't happen! i,j = %d,%d, minval = %d\n", procName, i, j, minval);
                continue;
            }
            if ((ia = iaaGetLinearTRC(iaa, maxval - minval)) == NULL) {
                L_ERROR("failure to make ia for j = %d!\n", procName, j);
                continue;
            }
            for (k = 0; k < sy && yoff + k < h; k++) {
                tline = line + k * wpl;
                for (m = 0; m < sx && xoff + m < w; m++) {
                    val = GET_DATA_BYTE(tline, xoff + m);
                    sval = val - minval;
                    sval = L_MAX(0, sval);
                    SET_DATA_BYTE(tline, xoff + m, ia[sval]);
                }
            }
        }
    }

    for (i = 0; i < 256; i++)
        LEPT_FREE(iaa[i]);
    LEPT_FREE(iaa);
    return pixd;
}



static l_int32 * iaaGetLinearTRC(l_int32  **iaa, l_int32    diff)

{
l_int32    i;
l_int32   *ia;
l_float32  factor;

    PROCNAME("iaaGetLinearTRC");

    if (!iaa)
        return (l_int32 *)ERROR_PTR("iaa not defined", procName, NULL);

    if (iaa[diff] != NULL)  
       return iaa[diff];

    if ((ia = (l_int32 *)LEPT_CALLOC(256, sizeof(l_int32))) == NULL)
        return (l_int32 *)ERROR_PTR("ia not made", procName, NULL);
    iaa[diff] = ia;
    if (diff == 0) {  
        for (i = 0; i < 256; i++)
            ia[i] = 128;
    }
    else {
        factor = 255. / (l_float32)diff;
        for (i = 0; i < diff + 1; i++)
            ia[i] = (l_int32)(factor * i + 0.5);
        for (i = diff + 1; i < 256; i++)
            ia[i] = 255;
    }

    return ia;
}
