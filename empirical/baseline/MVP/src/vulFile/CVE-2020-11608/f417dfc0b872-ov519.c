














MODULE_AUTHOR("Jean-Francois Moine <http://moinejf.free.fr>");
MODULE_DESCRIPTION("OV519 USB Camera Driver");
MODULE_LICENSE("GPL");


static int frame_rate;


static int i2c_detect_tries = 10;


struct sd {
	struct gspca_dev gspca_dev;		

	struct v4l2_ctrl *jpegqual;
	struct v4l2_ctrl *freq;
	struct { 
		struct v4l2_ctrl *hflip;
		struct v4l2_ctrl *vflip;
	};
	struct { 
		struct v4l2_ctrl *autobright;
		struct v4l2_ctrl *brightness;
	};

	u8 revision;

	u8 packet_nr;

	char bridge;









	char invert_led;


	char snapshot_pressed;
	char snapshot_needs_reset;

	
	u8 sif;





	u8 stopped;		
	u8 first_frame;

	u8 frame_rate;		
	u8 clockdiv;		

	s8 sensor;		

	u8 sensor_addr;
	u16 sensor_width;
	u16 sensor_height;
	s16 sensor_reg_cache[256];

	u8 jpeg_hdr[JPEG_HDR_SZ];
};
enum sensors {
	SEN_OV2610, SEN_OV2610AE, SEN_OV3610, SEN_OV6620, SEN_OV6630, SEN_OV66308AF, SEN_OV7610, SEN_OV7620, SEN_OV7620AE, SEN_OV7640, SEN_OV7648, SEN_OV7660, SEN_OV7670, SEN_OV76BE, SEN_OV8610, SEN_OV9600, };




















struct ctrl_valid {
	unsigned int has_brightness:1;
	unsigned int has_contrast:1;
	unsigned int has_exposure:1;
	unsigned int has_autogain:1;
	unsigned int has_sat:1;
	unsigned int has_hvflip:1;
	unsigned int has_autobright:1;
	unsigned int has_freq:1;
};

static const struct ctrl_valid valid_controls[] = {
	[SEN_OV2610] = {
		.has_exposure = 1, .has_autogain = 1, }, [SEN_OV2610AE] = {


		.has_exposure = 1, .has_autogain = 1, }, [SEN_OV3610] = {


		
	}, [SEN_OV6620] = {
		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV6630] = {





		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV66308AF] = {





		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV7610] = {





		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV7620] = {





		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV7620AE] = {





		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV7640] = {





		.has_brightness = 1, .has_sat = 1, .has_freq = 1, }, [SEN_OV7648] = {



		.has_brightness = 1, .has_sat = 1, .has_freq = 1, }, [SEN_OV7660] = {



		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_hvflip = 1, .has_freq = 1, }, [SEN_OV7670] = {





		.has_brightness = 1, .has_contrast = 1, .has_hvflip = 1, .has_freq = 1, }, [SEN_OV76BE] = {




		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, .has_freq = 1, }, [SEN_OV8610] = {





		.has_brightness = 1, .has_contrast = 1, .has_sat = 1, .has_autobright = 1, }, [SEN_OV9600] = {




		.has_exposure = 1, .has_autogain = 1, }, };



static const struct v4l2_pix_format ov519_vga_mode[] = {
	{320, 240, V4L2_PIX_FMT_JPEG, V4L2_FIELD_NONE, .bytesperline = 320, .sizeimage = 320 * 240 * 3 / 8 + 590, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 1}, {640, 480, V4L2_PIX_FMT_JPEG, V4L2_FIELD_NONE, .bytesperline = 640, .sizeimage = 640 * 480 * 3 / 8 + 590, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 0}, };









static const struct v4l2_pix_format ov519_sif_mode[] = {
	{160, 120, V4L2_PIX_FMT_JPEG, V4L2_FIELD_NONE, .bytesperline = 160, .sizeimage = 160 * 120 * 3 / 8 + 590, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 3}, {176, 144, V4L2_PIX_FMT_JPEG, V4L2_FIELD_NONE, .bytesperline = 176, .sizeimage = 176 * 144 * 3 / 8 + 590, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 1}, {320, 240, V4L2_PIX_FMT_JPEG, V4L2_FIELD_NONE, .bytesperline = 320, .sizeimage = 320 * 240 * 3 / 8 + 590, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 2}, {352, 288, V4L2_PIX_FMT_JPEG, V4L2_FIELD_NONE, .bytesperline = 352, .sizeimage = 352 * 288 * 3 / 8 + 590, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 0}, };





















static const struct v4l2_pix_format ov518_vga_mode[] = {
	{320, 240, V4L2_PIX_FMT_OV518, V4L2_FIELD_NONE, .bytesperline = 320, .sizeimage = 320 * 240 * 3, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 1}, {640, 480, V4L2_PIX_FMT_OV518, V4L2_FIELD_NONE, .bytesperline = 640, .sizeimage = 640 * 480 * 2, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 0}, };









static const struct v4l2_pix_format ov518_sif_mode[] = {
	{160, 120, V4L2_PIX_FMT_OV518, V4L2_FIELD_NONE, .bytesperline = 160, .sizeimage = 70000, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 3}, {176, 144, V4L2_PIX_FMT_OV518, V4L2_FIELD_NONE, .bytesperline = 176, .sizeimage = 70000, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 1}, {320, 240, V4L2_PIX_FMT_OV518, V4L2_FIELD_NONE, .bytesperline = 320, .sizeimage = 320 * 240 * 3, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 2}, {352, 288, V4L2_PIX_FMT_OV518, V4L2_FIELD_NONE, .bytesperline = 352, .sizeimage = 352 * 288 * 3, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 0}, };




















static const struct v4l2_pix_format ov511_vga_mode[] = {
	{320, 240, V4L2_PIX_FMT_OV511, V4L2_FIELD_NONE, .bytesperline = 320, .sizeimage = 320 * 240 * 3, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 1}, {640, 480, V4L2_PIX_FMT_OV511, V4L2_FIELD_NONE, .bytesperline = 640, .sizeimage = 640 * 480 * 2, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 0}, };









static const struct v4l2_pix_format ov511_sif_mode[] = {
	{160, 120, V4L2_PIX_FMT_OV511, V4L2_FIELD_NONE, .bytesperline = 160, .sizeimage = 70000, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 3}, {176, 144, V4L2_PIX_FMT_OV511, V4L2_FIELD_NONE, .bytesperline = 176, .sizeimage = 70000, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 1}, {320, 240, V4L2_PIX_FMT_OV511, V4L2_FIELD_NONE, .bytesperline = 320, .sizeimage = 320 * 240 * 3, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 2}, {352, 288, V4L2_PIX_FMT_OV511, V4L2_FIELD_NONE, .bytesperline = 352, .sizeimage = 352 * 288 * 3, .colorspace = V4L2_COLORSPACE_JPEG, .priv = 0}, };




















static const struct v4l2_pix_format ovfx2_ov2610_mode[] = {
	{800, 600, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 800, .sizeimage = 800 * 600, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 1}, {1600, 1200, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 1600, .sizeimage = 1600 * 1200, .colorspace = V4L2_COLORSPACE_SRGB}, };








static const struct v4l2_pix_format ovfx2_ov3610_mode[] = {
	{640, 480, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 640, .sizeimage = 640 * 480, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 1}, {800, 600, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 800, .sizeimage = 800 * 600, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 1}, {1024, 768, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 1024, .sizeimage = 1024 * 768, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 1}, {1600, 1200, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 1600, .sizeimage = 1600 * 1200, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 0}, {2048, 1536, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 2048, .sizeimage = 2048 * 1536, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 0}, };
























static const struct v4l2_pix_format ovfx2_ov9600_mode[] = {
	{640, 480, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 640, .sizeimage = 640 * 480, .colorspace = V4L2_COLORSPACE_SRGB, .priv = 1}, {1280, 1024, V4L2_PIX_FMT_SBGGR8, V4L2_FIELD_NONE, .bytesperline = 1280, .sizeimage = 1280 * 1024, .colorspace = V4L2_COLORSPACE_SRGB}, };












	
	#define	OV511_RESET_OMNICE	0x08




























































































































































struct ov_regvals {
	u8 reg;
	u8 val;
};
struct ov_i2c_regvals {
	u8 reg;
	u8 val;
};


static const struct ov_i2c_regvals norm_2610[] = {
	{ 0x12, 0x80 },	 };

static const struct ov_i2c_regvals norm_2610ae[] = {
	{0x12, 0x80},	 {0x13, 0xcd}, {0x09, 0x01}, {0x0d, 0x00}, {0x11, 0x80}, {0x12, 0x20}, {0x33, 0x0c}, {0x35, 0x90}, {0x36, 0x37},  {0x11, 0x83}, {0x2d, 0x00}, {0x24, 0xb0}, {0x25, 0x90}, {0x10, 0x43}, };















static const struct ov_i2c_regvals norm_3620b[] = {
	
	{ 0x12, 0x80 },  { 0x12, 0x00 },   { 0x11, 0x80 },   { 0x13, 0xc0 },   { 0x09, 0x08 },   { 0x0c, 0x08 },   { 0x0d, 0xa1 },   { 0x0e, 0x70 },   { 0x0f, 0x42 },   { 0x14, 0xc6 },   { 0x15, 0x02 },   { 0x33, 0x09 },   { 0x34, 0x50 },   { 0x36, 0x00 },   { 0x37, 0x04 },   { 0x38, 0x52 },   { 0x3a, 0x00 },   { 0x3c, 0x1f },   { 0x44, 0x00 },   { 0x40, 0x00 },   { 0x41, 0x00 },   { 0x42, 0x00 },   { 0x43, 0x00 },   { 0x45, 0x80 },   { 0x48, 0xc0 },   { 0x49, 0x19 },   { 0x4b, 0x80 },   { 0x4d, 0xc4 },   { 0x35, 0x4c },   { 0x3d, 0x00 },   { 0x3e, 0x00 },   { 0x3b, 0x18 },   { 0x33, 0x19 },   { 0x34, 0x5a },   { 0x3b, 0x00 },   { 0x33, 0x09 },   { 0x34, 0x50 },   { 0x12, 0x40 },   { 0x17, 0x1f },   { 0x18, 0x5f },   { 0x19, 0x00 },   { 0x1a, 0x60 },   { 0x32, 0x12 },   { 0x03, 0x4a },   { 0x11, 0x80 },   { 0x12, 0x00 },   { 0x12, 0x40 },   { 0x17, 0x1f },   { 0x18, 0x5f },   { 0x19, 0x00 },   { 0x1a, 0x60 },   { 0x32, 0x12 },   { 0x03, 0x4a },   { 0x02, 0xaf },   { 0x2d, 0xd2 },   { 0x00, 0x18 },   { 0x01, 0xf0 },   { 0x10, 0x0a },  { 0xe1, 0x67 }, { 0xe3, 0x03 }, { 0xe4, 0x26 }, { 0xe5, 0x3e }, { 0xf8, 0x01 }, { 0xff, 0x01 }, };

















































































































































































static const struct ov_i2c_regvals norm_6x20[] = {
	{ 0x12, 0x80 },  { 0x11, 0x01 }, { 0x03, 0x60 }, { 0x05, 0x7f }, { 0x07, 0xa8 },  { 0x0c, 0x24 }, { 0x0d, 0x24 }, { 0x0f, 0x15 }, { 0x10, 0x75 }, { 0x12, 0x24 }, { 0x14, 0x04 },  { 0x16, 0x06 },  { 0x26, 0xb2 },  { 0x28, 0x05 }, { 0x2a, 0x04 },  { 0x2d, 0x85 }, { 0x33, 0xa0 }, { 0x34, 0xd2 }, { 0x38, 0x8b }, { 0x39, 0x40 },  { 0x3c, 0x39 }, { 0x3c, 0x3c }, { 0x3c, 0x24 },  { 0x3d, 0x80 },  { 0x4a, 0x80 }, { 0x4b, 0x80 }, { 0x4d, 0xd2 }, { 0x4e, 0xc1 }, { 0x4f, 0x04 },   };







































static const struct ov_i2c_regvals norm_6x30[] = {
	{ 0x12, 0x80 },  { 0x00, 0x1f }, { 0x01, 0x99 }, { 0x02, 0x7c }, { 0x03, 0xc0 }, { 0x05, 0x0a }, { 0x06, 0x95 }, { 0x07, 0x2d }, { 0x0c, 0x20 }, { 0x0d, 0x20 }, { 0x0e, 0xa0 }, { 0x0f, 0x05 }, { 0x10, 0x9a }, { 0x11, 0x00 }, { 0x12, 0x24 }, { 0x13, 0x21 }, { 0x14, 0x80 }, { 0x15, 0x01 }, { 0x16, 0x03 }, { 0x17, 0x38 }, { 0x18, 0xea }, { 0x19, 0x04 }, { 0x1a, 0x93 }, { 0x1b, 0x00 }, { 0x1e, 0xc4 }, { 0x1f, 0x04 }, { 0x20, 0x20 }, { 0x21, 0x10 }, { 0x22, 0x88 }, { 0x23, 0xc0 }, { 0x25, 0x9a }, { 0x26, 0xb2 }, { 0x27, 0xa2 }, { 0x28, 0x00 }, { 0x29, 0x00 }, { 0x2a, 0x84 }, { 0x2b, 0xa8 }, { 0x2c, 0xa0 }, { 0x2d, 0x95 }, { 0x2e, 0x88 }, { 0x33, 0x26 }, { 0x34, 0x03 }, { 0x36, 0x8f }, { 0x37, 0x80 }, { 0x38, 0x83 }, { 0x39, 0x80 }, { 0x3a, 0x0f }, { 0x3b, 0x3c }, { 0x3c, 0x1a }, { 0x3d, 0x80 }, { 0x3e, 0x80 }, { 0x3f, 0x0e }, { 0x40, 0x00 }, { 0x41, 0x00 }, { 0x42, 0x80 }, { 0x43, 0x3f }, { 0x44, 0x80 }, { 0x45, 0x20 }, { 0x46, 0x20 }, { 0x47, 0x80 }, { 0x48, 0x7f }, { 0x49, 0x00 }, { 0x4a, 0x00 }, { 0x4b, 0x80 }, { 0x4c, 0xd0 }, { 0x4d, 0x10 }, { 0x4e, 0x40 }, { 0x4f, 0x07 }, { 0x50, 0xff }, { 0x54, 0x23 }, { 0x55, 0xff }, { 0x56, 0x12 }, { 0x57, 0x81 }, { 0x58, 0x75 }, { 0x59, 0x01 }, { 0x5a, 0x2c }, { 0x5b, 0x0f }, { 0x5c, 0x10 }, { 0x3d, 0x80 }, { 0x27, 0xa6 }, { 0x12, 0x20 }, { 0x12, 0x24 }, };



















































































static const struct ov_i2c_regvals norm_7610[] = {
	{ 0x10, 0xff }, { 0x16, 0x06 }, { 0x28, 0x24 }, { 0x2b, 0xac }, { 0x12, 0x00 }, { 0x38, 0x81 }, { 0x28, 0x24 }, { 0x0f, 0x85 }, { 0x15, 0x01 }, { 0x20, 0x1c }, { 0x23, 0x2a }, { 0x24, 0x10 }, { 0x25, 0x8a }, { 0x26, 0xa2 }, { 0x27, 0xc2 }, { 0x2a, 0x04 }, { 0x2c, 0xfe }, { 0x2d, 0x93 }, { 0x30, 0x71 }, { 0x31, 0x60 }, { 0x32, 0x26 }, { 0x33, 0x20 }, { 0x34, 0x48 }, { 0x12, 0x24 }, { 0x11, 0x01 }, { 0x0c, 0x24 }, { 0x0d, 0x24 }, };



























static const struct ov_i2c_regvals norm_7620[] = {
	{ 0x12, 0x80 },		 { 0x00, 0x00 }, { 0x01, 0x80 }, { 0x02, 0x80 }, { 0x03, 0xc0 }, { 0x06, 0x60 }, { 0x07, 0x00 }, { 0x0c, 0x24 }, { 0x0c, 0x24 }, { 0x0d, 0x24 }, { 0x11, 0x01 }, { 0x12, 0x24 }, { 0x13, 0x01 }, { 0x14, 0x84 }, { 0x15, 0x01 }, { 0x16, 0x03 }, { 0x17, 0x2f }, { 0x18, 0xcf }, { 0x19, 0x06 }, { 0x1a, 0xf5 }, { 0x1b, 0x00 }, { 0x20, 0x18 }, { 0x21, 0x80 }, { 0x22, 0x80 }, { 0x23, 0x00 }, { 0x26, 0xa2 }, { 0x27, 0xea }, { 0x28, 0x22 }, { 0x29, 0x00 }, { 0x2a, 0x10 }, { 0x2b, 0x00 }, { 0x2c, 0x88 }, { 0x2d, 0x91 }, { 0x2e, 0x80 }, { 0x2f, 0x44 }, { 0x60, 0x27 }, { 0x61, 0x02 }, { 0x62, 0x5f }, { 0x63, 0xd5 }, { 0x64, 0x57 }, { 0x65, 0x83 }, { 0x66, 0x55 }, { 0x67, 0x92 }, { 0x68, 0xcf }, { 0x69, 0x76 }, { 0x6a, 0x22 }, { 0x6b, 0x00 }, { 0x6c, 0x02 }, { 0x6d, 0x44 }, { 0x6e, 0x80 }, { 0x6f, 0x1d }, { 0x70, 0x8b }, { 0x71, 0x00 }, { 0x72, 0x14 }, { 0x73, 0x54 }, { 0x74, 0x00 }, { 0x75, 0x8e }, { 0x76, 0x00 }, { 0x77, 0xff }, { 0x78, 0x80 }, { 0x79, 0x80 }, { 0x7a, 0x80 }, { 0x7b, 0xe2 }, { 0x7c, 0x00 }, };

































































static const struct ov_i2c_regvals norm_7640[] = {
	{ 0x12, 0x80 }, { 0x12, 0x14 }, };


static const struct ov_regvals init_519_ov7660[] = {
	{ 0x5d,	0x03 },  { 0x53,	0x9b }, { 0x54,	0x0f }, { 0xa2,	0x20 }, { 0xa3,	0x18 }, { 0xa4,	0x04 }, { 0xa5,	0x28 }, { 0x37,	0x00 }, { 0x55,	0x02 },  { 0x20,	0x0c }, { 0x21,	0x38 }, { 0x22,	0x1d }, { 0x17,	0x50 }, { 0x37,	0x00 }, { 0x40,	0xff }, { 0x46,	0x00 }, };
















static const struct ov_i2c_regvals norm_7660[] = {
	{OV7670_R12_COM7, OV7670_COM7_RESET}, {OV7670_R11_CLKRC, 0x81}, {0x92, 0x00}, {0x93, 0x00}, {0x9d, 0x4c}, {0x9e, 0x3f}, {OV7670_R3B_COM11, 0x02}, {OV7670_R13_COM8, 0xf5}, {OV7670_R10_AECH, 0x00}, {OV7670_R00_GAIN, 0x00}, {OV7670_R01_BLUE, 0x7c}, {OV7670_R02_RED, 0x9d}, {OV7670_R12_COM7, 0x00}, {OV7670_R04_COM1, 00}, {OV7670_R18_HSTOP, 0x01}, {OV7670_R17_HSTART, 0x13}, {OV7670_R32_HREF, 0x92}, {OV7670_R19_VSTART, 0x02}, {OV7670_R1A_VSTOP, 0x7a}, {OV7670_R03_VREF, 0x00}, {OV7670_R0E_COM5, 0x04}, {OV7670_R0F_COM6, 0x62}, {OV7670_R15_COM10, 0x00}, {0x16, 0x02}, {0x1b, 0x00}, {OV7670_R1E_MVFP, 0x01}, {0x29, 0x3c}, {0x33, 0x00}, {0x34, 0x07}, {0x35, 0x84}, {0x36, 0x00}, {0x37, 0x04}, {0x39, 0x43}, {OV7670_R3A_TSLB, 0x00}, {OV7670_R3C_COM12, 0x6c}, {OV7670_R3D_COM13, 0x98}, {OV7670_R3F_EDGE, 0x23}, {OV7670_R40_COM15, 0xc1}, {OV7670_R41_COM16, 0x22}, {0x6b, 0x0a}, {0xa1, 0x08}, {0x69, 0x80}, {0x43, 0xf0}, {0x44, 0x10}, {0x45, 0x78}, {0x46, 0xa8}, {0x47, 0x60}, {0x48, 0x80}, {0x59, 0xba}, {0x5a, 0x9a}, {0x5b, 0x22}, {0x5c, 0xb9}, {0x5d, 0x9b}, {0x5e, 0x10}, {0x5f, 0xe0}, {0x60, 0x85}, {0x61, 0x60}, {0x9f, 0x9d}, {0xa0, 0xa0}, {0x4f, 0x60}, {0x50, 0x64}, {0x51, 0x04}, {0x52, 0x18}, {0x53, 0x3c}, {0x54, 0x54}, {0x55, 0x40}, {0x56, 0x40}, {0x57, 0x40}, {0x58, 0x0d}, {0x8b, 0xcc}, {0x8c, 0xcc}, {0x8d, 0xcf}, {0x6c, 0x40}, {0x6d, 0xe0}, {0x6e, 0xa0}, {0x6f, 0x80}, {0x70, 0x70}, {0x71, 0x80}, {0x72, 0x60}, {0x73, 0x60}, {0x74, 0x50}, {0x75, 0x40}, {0x76, 0x38}, {0x77, 0x3c}, {0x78, 0x32}, {0x79, 0x1a}, {0x7a, 0x28}, {0x7b, 0x24}, {0x7c, 0x04}, {0x7d, 0x12}, {0x7e, 0x26}, {0x7f, 0x46}, {0x80, 0x54}, {0x81, 0x64}, {0x82, 0x70}, {0x83, 0x7c}, {0x84, 0x86}, {0x85, 0x8e}, {0x86, 0x9c}, {0x87, 0xab}, {0x88, 0xc4}, {0x89, 0xd1}, {0x8a, 0xe5}, {OV7670_R14_COM9, 0x1e}, {OV7670_R24_AEW, 0x80}, {OV7670_R25_AEB, 0x72}, {OV7670_R26_VPT, 0xb3}, {0x62, 0x80}, {0x63, 0x80}, {0x64, 0x06}, {0x65, 0x00}, {0x66, 0x01}, {0x94, 0x0e}, {0x95, 0x14}, {OV7670_R13_COM8, OV7670_COM8_FASTAEC | OV7670_COM8_AECSTEP | OV7670_COM8_BFILT | 0x10 | OV7670_COM8_AGC | OV7670_COM8_AWB | OV7670_COM8_AEC}, {0xa1, 0xc8}
























































































































};
static const struct ov_i2c_regvals norm_9600[] = {
	{0x12, 0x80}, {0x0c, 0x28}, {0x11, 0x80}, {0x13, 0xb5}, {0x14, 0x3e}, {0x1b, 0x04}, {0x24, 0xb0}, {0x25, 0x90}, {0x26, 0x94}, {0x35, 0x90}, {0x37, 0x07}, {0x38, 0x08}, {0x01, 0x8e}, {0x02, 0x85}












};


static const struct ov_i2c_regvals norm_7670[] = {
	{ OV7670_R12_COM7, OV7670_COM7_RESET }, { OV7670_R3A_TSLB, 0x04 }, { OV7670_R12_COM7, OV7670_COM7_FMT_VGA }, { OV7670_R11_CLKRC, 0x01 },  { OV7670_R17_HSTART, 0x13 }, { OV7670_R18_HSTOP, 0x01 }, { OV7670_R32_HREF, 0xb6 }, { OV7670_R19_VSTART, 0x02 }, { OV7670_R1A_VSTOP, 0x7a }, { OV7670_R03_VREF, 0x0a },  { OV7670_R0C_COM3, 0x00 }, { OV7670_R3E_COM14, 0x00 },  { 0x70, 0x3a }, { 0x71, 0x35 }, { 0x72, 0x11 }, { 0x73, 0xf0 }, { 0xa2, 0x02 },    { 0x7a, 0x20 }, { 0x7b, 0x10 }, { 0x7c, 0x1e }, { 0x7d, 0x35 }, { 0x7e, 0x5a }, { 0x7f, 0x69 }, { 0x80, 0x76 }, { 0x81, 0x80 }, { 0x82, 0x88 }, { 0x83, 0x8f }, { 0x84, 0x96 }, { 0x85, 0xa3 }, { 0x86, 0xaf }, { 0x87, 0xc4 }, { 0x88, 0xd7 }, { 0x89, 0xe8 },   { OV7670_R13_COM8, OV7670_COM8_FASTAEC | OV7670_COM8_AECSTEP | OV7670_COM8_BFILT }, { OV7670_R00_GAIN, 0x00 }, { OV7670_R10_AECH, 0x00 }, { OV7670_R0D_COM4, 0x40 }, { OV7670_R14_COM9, 0x18 }, { OV7670_RA5_BD50MAX, 0x05 }, { OV7670_RAB_BD60MAX, 0x07 }, { OV7670_R24_AEW, 0x95 }, { OV7670_R25_AEB, 0x33 }, { OV7670_R26_VPT, 0xe3 }, { OV7670_R9F_HAECC1, 0x78 }, { OV7670_RA0_HAECC2, 0x68 }, { 0xa1, 0x03 }, { OV7670_RA6_HAECC3, 0xd8 }, { OV7670_RA7_HAECC4, 0xd8 }, { OV7670_RA8_HAECC5, 0xf0 }, { OV7670_RA9_HAECC6, 0x90 }, { OV7670_RAA_HAECC7, 0x94 }, { OV7670_R13_COM8, OV7670_COM8_FASTAEC | OV7670_COM8_AECSTEP | OV7670_COM8_BFILT | OV7670_COM8_AGC | OV7670_COM8_AEC },   { OV7670_R0E_COM5, 0x61 }, { OV7670_R0F_COM6, 0x4b }, { 0x16, 0x02 }, { OV7670_R1E_MVFP, 0x07 }, { 0x21, 0x02 }, { 0x22, 0x91 }, { 0x29, 0x07 }, { 0x33, 0x0b }, { 0x35, 0x0b }, { 0x37, 0x1d }, { 0x38, 0x71 }, { 0x39, 0x2a }, { OV7670_R3C_COM12, 0x78 }, { 0x4d, 0x40 }, { 0x4e, 0x20 }, { OV7670_R69_GFIX, 0x00 }, { 0x6b, 0x4a }, { 0x74, 0x10 }, { 0x8d, 0x4f }, { 0x8e, 0x00 }, { 0x8f, 0x00 }, { 0x90, 0x00 }, { 0x91, 0x00 }, { 0x96, 0x00 }, { 0x9a, 0x00 }, { 0xb0, 0x84 }, { 0xb1, 0x0c }, { 0xb2, 0x0e }, { 0xb3, 0x82 }, { 0xb8, 0x0a },   { 0x43, 0x0a }, { 0x44, 0xf0 }, { 0x45, 0x34 }, { 0x46, 0x58 }, { 0x47, 0x28 }, { 0x48, 0x3a }, { 0x59, 0x88 }, { 0x5a, 0x88 }, { 0x5b, 0x44 }, { 0x5c, 0x67 }, { 0x5d, 0x49 }, { 0x5e, 0x0e }, { 0x6c, 0x0a }, { 0x6d, 0x55 }, { 0x6e, 0x11 }, { 0x6f, 0x9f }, { 0x6a, 0x40 }, { OV7670_R01_BLUE, 0x40 }, { OV7670_R02_RED, 0x60 }, { OV7670_R13_COM8, OV7670_COM8_FASTAEC | OV7670_COM8_AECSTEP | OV7670_COM8_BFILT | OV7670_COM8_AGC | OV7670_COM8_AEC | OV7670_COM8_AWB },   { 0x4f, 0x80 }, { 0x50, 0x80 }, { 0x51, 0x00 }, { 0x52, 0x22 }, { 0x53, 0x5e }, { 0x54, 0x80 }, { 0x58, 0x9e },  { OV7670_R41_COM16, OV7670_COM16_AWBGAIN }, { OV7670_R3F_EDGE, 0x00 }, { 0x75, 0x05 }, { 0x76, 0xe1 }, { 0x4c, 0x00 }, { 0x77, 0x01 }, { OV7670_R3D_COM13, OV7670_COM13_GAMMA | OV7670_COM13_UVSAT | 2}, { 0x4b, 0x09 }, { 0xc9, 0x60 }, { OV7670_R41_COM16, 0x38 }, { 0x56, 0x40 },  { 0x34, 0x11 }, { OV7670_R3B_COM11, OV7670_COM11_EXP|OV7670_COM11_HZAUTO }, { 0xa4, 0x88 }, { 0x96, 0x00 }, { 0x97, 0x30 }, { 0x98, 0x20 }, { 0x99, 0x30 }, { 0x9a, 0x84 }, { 0x9b, 0x29 }, { 0x9c, 0x03 }, { 0x9d, 0x4c }, { 0x9e, 0x3f }, { 0x78, 0x04 },   { 0x79, 0x01 }, { 0xc8, 0xf0 }, { 0x79, 0x0f }, { 0xc8, 0x00 }, { 0x79, 0x10 }, { 0xc8, 0x7e }, { 0x79, 0x0a }, { 0xc8, 0x80 }, { 0x79, 0x0b }, { 0xc8, 0x01 }, { 0x79, 0x0c }, { 0xc8, 0x0f }, { 0x79, 0x0d }, { 0xc8, 0x20 }, { 0x79, 0x09 }, { 0xc8, 0x80 }, { 0x79, 0x02 }, { 0xc8, 0xc0 }, { 0x79, 0x03 }, { 0xc8, 0x40 }, { 0x79, 0x05 }, { 0xc8, 0x30 }, { 0x79, 0x26 }, };



























































































































































































static const struct ov_i2c_regvals norm_8610[] = {
	{ 0x12, 0x80 }, { 0x00, 0x00 }, { 0x01, 0x80 }, { 0x02, 0x80 }, { 0x03, 0xc0 }, { 0x04, 0x30 }, { 0x05, 0x30 }, { 0x06, 0x70 }, { 0x0a, 0x86 }, { 0x0b, 0xb0 }, { 0x0c, 0x20 }, { 0x0d, 0x20 }, { 0x11, 0x01 }, { 0x12, 0x25 }, { 0x13, 0x01 }, { 0x14, 0x04 }, { 0x15, 0x01 }, { 0x16, 0x03 }, { 0x17, 0x38 }, { 0x18, 0xea }, { 0x19, 0x02 }, { 0x1a, 0xf5 }, { 0x1b, 0x00 }, { 0x20, 0xd0 }, { 0x23, 0xc0 }, { 0x24, 0x30 }, { 0x25, 0x50 }, { 0x26, 0xa2 }, { 0x27, 0xea }, { 0x28, 0x00 }, { 0x29, 0x00 }, { 0x2a, 0x80 }, { 0x2b, 0xc8 }, { 0x2c, 0xac }, { 0x2d, 0x45 }, { 0x2e, 0x80 }, { 0x2f, 0x14 }, { 0x4c, 0x00 }, { 0x4d, 0x30 }, { 0x60, 0x02 }, { 0x61, 0x00 }, { 0x62, 0x5f }, { 0x63, 0xff }, { 0x64, 0x53 }, { 0x65, 0x00 }, { 0x66, 0x55 }, { 0x67, 0xb0 }, { 0x68, 0xc0 }, { 0x69, 0x02 }, { 0x6a, 0x22 }, { 0x6b, 0x00 }, { 0x6c, 0x99 }, { 0x6d, 0x11 }, { 0x6e, 0x11 }, { 0x6f, 0x01 }, { 0x70, 0x8b }, { 0x71, 0x00 }, { 0x72, 0x14 }, { 0x73, 0x54 }, { 0x74, 0x00 }, { 0x75, 0x0e }, { 0x76, 0x02 }, { 0x77, 0xff }, { 0x78, 0x80 }, { 0x79, 0x80 }, { 0x7a, 0x80 }, { 0x7b, 0x10 }, { 0x7c, 0x00 }, { 0x7d, 0x08 }, { 0x7e, 0x08 }, { 0x7f, 0xfb }, { 0x80, 0x28 }, { 0x81, 0x00 }, { 0x82, 0x23 }, { 0x83, 0x0b }, { 0x84, 0x00 }, { 0x85, 0x62 }, { 0x86, 0xc9 }, { 0x87, 0x00 }, { 0x88, 0x00 }, { 0x89, 0x01 }, { 0x12, 0x20 }, { 0x12, 0x25 }, };



















































































static unsigned char ov7670_abs_to_sm(unsigned char v)
{
	if (v > 127)
		return v & 0x7f;
	return (128 - v) | 0x80;
}


static void reg_w(struct sd *sd, u16 index, u16 value)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int ret, req = 0;

	if (sd->gspca_dev.usb_err < 0)
		return;

	
	udelay(150);

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		req = 2;
		break;
	case BRIDGE_OVFX2:
		req = 0x0a;
		
	case BRIDGE_W9968CF:
		gspca_dbg(gspca_dev, D_USBO, "SET %02x %04x %04x\n", req, value, index);
		ret = usb_control_msg(sd->gspca_dev.dev, usb_sndctrlpipe(sd->gspca_dev.dev, 0), req, USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE, value, index, NULL, 0, 500);



		goto leave;
	default:
		req = 1;
	}

	gspca_dbg(gspca_dev, D_USBO, "SET %02x 0000 %04x %02x\n", req, index, value);
	sd->gspca_dev.usb_buf[0] = value;
	ret = usb_control_msg(sd->gspca_dev.dev, usb_sndctrlpipe(sd->gspca_dev.dev, 0), req, USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, index, sd->gspca_dev.usb_buf, 1, 500);




leave:
	if (ret < 0) {
		gspca_err(gspca_dev, "reg_w %02x failed %d\n", index, ret);
		sd->gspca_dev.usb_err = ret;
		return;
	}
}



static int reg_r(struct sd *sd, u16 index)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int ret;
	int req;

	if (sd->gspca_dev.usb_err < 0)
		return -1;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		req = 3;
		break;
	case BRIDGE_OVFX2:
		req = 0x0b;
		break;
	default:
		req = 1;
	}

	
	udelay(150);
	ret = usb_control_msg(sd->gspca_dev.dev, usb_rcvctrlpipe(sd->gspca_dev.dev, 0), req, USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, index, sd->gspca_dev.usb_buf, 1, 500);




	if (ret >= 0) {
		ret = sd->gspca_dev.usb_buf[0];
		gspca_dbg(gspca_dev, D_USBI, "GET %02x 0000 %04x %02x\n", req, index, ret);
	} else {
		gspca_err(gspca_dev, "reg_r %02x failed %d\n", index, ret);
		sd->gspca_dev.usb_err = ret;
		
		gspca_dev->usb_buf[0] = 0;
	}

	return ret;
}


static int reg_r8(struct sd *sd, u16 index)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int ret;

	if (sd->gspca_dev.usb_err < 0)
		return -1;

	
	udelay(150);
	ret = usb_control_msg(sd->gspca_dev.dev, usb_rcvctrlpipe(sd->gspca_dev.dev, 0), 1, USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, index, sd->gspca_dev.usb_buf, 8, 500);




	if (ret >= 0) {
		ret = sd->gspca_dev.usb_buf[0];
	} else {
		gspca_err(gspca_dev, "reg_r8 %02x failed %d\n", index, ret);
		sd->gspca_dev.usb_err = ret;
		
		memset(gspca_dev->usb_buf, 0, 8);
	}

	return ret;
}


static void reg_w_mask(struct sd *sd, u16 index, u8 value, u8 mask)


{
	int ret;
	u8 oldval;

	if (mask != 0xff) {
		value &= mask;			
		ret = reg_r(sd, index);
		if (ret < 0)
			return;

		oldval = ret & ~mask;		
		value |= oldval;		
	}
	reg_w(sd, index, value);
}


static void ov518_reg_w32(struct sd *sd, u16 index, u32 value, int n)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int ret;

	if (sd->gspca_dev.usb_err < 0)
		return;

	*((__le32 *) sd->gspca_dev.usb_buf) = __cpu_to_le32(value);

	
	udelay(150);
	ret = usb_control_msg(sd->gspca_dev.dev, usb_sndctrlpipe(sd->gspca_dev.dev, 0), 1 , USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, index, sd->gspca_dev.usb_buf, n, 500);




	if (ret < 0) {
		gspca_err(gspca_dev, "reg_w32 %02x failed %d\n", index, ret);
		sd->gspca_dev.usb_err = ret;
	}
}

static void ov511_i2c_w(struct sd *sd, u8 reg, u8 value)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int rc, retries;

	gspca_dbg(gspca_dev, D_USBO, "ov511_i2c_w %02x %02x\n", reg, value);

	
	for (retries = 6; ; ) {
		
		reg_w(sd, R51x_I2C_SADDR_3, reg);

		
		reg_w(sd, R51x_I2C_DATA, value);

		
		reg_w(sd, R511_I2C_CTL, 0x01);

		do {
			rc = reg_r(sd, R511_I2C_CTL);
		} while (rc > 0 && ((rc & 1) == 0)); 

		if (rc < 0)
			return;

		if ((rc & 2) == 0) 
			break;
		if (--retries < 0) {
			gspca_dbg(gspca_dev, D_USBO, "i2c write retries exhausted\n");
			return;
		}
	}
}

static int ov511_i2c_r(struct sd *sd, u8 reg)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int rc, value, retries;

	
	for (retries = 6; ; ) {
		
		reg_w(sd, R51x_I2C_SADDR_2, reg);

		
		reg_w(sd, R511_I2C_CTL, 0x03);

		do {
			rc = reg_r(sd, R511_I2C_CTL);
		} while (rc > 0 && ((rc & 1) == 0)); 

		if (rc < 0)
			return rc;

		if ((rc & 2) == 0) 
			break;

		
		reg_w(sd, R511_I2C_CTL, 0x10);

		if (--retries < 0) {
			gspca_dbg(gspca_dev, D_USBI, "i2c write retries exhausted\n");
			return -1;
		}
	}

	
	for (retries = 6; ; ) {
		
		reg_w(sd, R511_I2C_CTL, 0x05);

		do {
			rc = reg_r(sd, R511_I2C_CTL);
		} while (rc > 0 && ((rc & 1) == 0)); 

		if (rc < 0)
			return rc;

		if ((rc & 2) == 0) 
			break;

		
		reg_w(sd, R511_I2C_CTL, 0x10);

		if (--retries < 0) {
			gspca_dbg(gspca_dev, D_USBI, "i2c read retries exhausted\n");
			return -1;
		}
	}

	value = reg_r(sd, R51x_I2C_DATA);

	gspca_dbg(gspca_dev, D_USBI, "ov511_i2c_r %02x %02x\n", reg, value);

	
	reg_w(sd, R511_I2C_CTL, 0x05);

	return value;
}


static void ov518_i2c_w(struct sd *sd, u8 reg, u8 value)

{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;

	gspca_dbg(gspca_dev, D_USBO, "ov518_i2c_w %02x %02x\n", reg, value);

	
	reg_w(sd, R51x_I2C_SADDR_3, reg);

	
	reg_w(sd, R51x_I2C_DATA, value);

	
	reg_w(sd, R518_I2C_CTL, 0x01);

	
	msleep(4);
	reg_r8(sd, R518_I2C_CTL);
}


static int ov518_i2c_r(struct sd *sd, u8 reg)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int value;

	
	reg_w(sd, R51x_I2C_SADDR_2, reg);

	
	reg_w(sd, R518_I2C_CTL, 0x03);
	reg_r8(sd, R518_I2C_CTL);

	
	reg_w(sd, R518_I2C_CTL, 0x05);
	reg_r8(sd, R518_I2C_CTL);

	value = reg_r(sd, R51x_I2C_DATA);
	gspca_dbg(gspca_dev, D_USBI, "ov518_i2c_r %02x %02x\n", reg, value);
	return value;
}

static void ovfx2_i2c_w(struct sd *sd, u8 reg, u8 value)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int ret;

	if (sd->gspca_dev.usb_err < 0)
		return;

	ret = usb_control_msg(sd->gspca_dev.dev, usb_sndctrlpipe(sd->gspca_dev.dev, 0), 0x02, USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE, (u16) value, (u16) reg, NULL, 0, 500);




	if (ret < 0) {
		gspca_err(gspca_dev, "ovfx2_i2c_w %02x failed %d\n", reg, ret);
		sd->gspca_dev.usb_err = ret;
	}

	gspca_dbg(gspca_dev, D_USBO, "ovfx2_i2c_w %02x %02x\n", reg, value);
}

static int ovfx2_i2c_r(struct sd *sd, u8 reg)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int ret;

	if (sd->gspca_dev.usb_err < 0)
		return -1;

	ret = usb_control_msg(sd->gspca_dev.dev, usb_rcvctrlpipe(sd->gspca_dev.dev, 0), 0x03, USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0, (u16) reg, sd->gspca_dev.usb_buf, 1, 500);




	if (ret >= 0) {
		ret = sd->gspca_dev.usb_buf[0];
		gspca_dbg(gspca_dev, D_USBI, "ovfx2_i2c_r %02x %02x\n", reg, ret);
	} else {
		gspca_err(gspca_dev, "ovfx2_i2c_r %02x failed %d\n", reg, ret);
		sd->gspca_dev.usb_err = ret;
	}

	return ret;
}

static void i2c_w(struct sd *sd, u8 reg, u8 value)
{
	if (sd->sensor_reg_cache[reg] == value)
		return;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		ov511_i2c_w(sd, reg, value);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
	case BRIDGE_OV519:
		ov518_i2c_w(sd, reg, value);
		break;
	case BRIDGE_OVFX2:
		ovfx2_i2c_w(sd, reg, value);
		break;
	case BRIDGE_W9968CF:
		w9968cf_i2c_w(sd, reg, value);
		break;
	}

	if (sd->gspca_dev.usb_err >= 0) {
		
		if (reg == 0x12 && (value & 0x80))
			memset(sd->sensor_reg_cache, -1, sizeof(sd->sensor_reg_cache));
		else sd->sensor_reg_cache[reg] = value;
	}
}

static int i2c_r(struct sd *sd, u8 reg)
{
	int ret = -1;

	if (sd->sensor_reg_cache[reg] != -1)
		return sd->sensor_reg_cache[reg];

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		ret = ov511_i2c_r(sd, reg);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
	case BRIDGE_OV519:
		ret = ov518_i2c_r(sd, reg);
		break;
	case BRIDGE_OVFX2:
		ret = ovfx2_i2c_r(sd, reg);
		break;
	case BRIDGE_W9968CF:
		ret = w9968cf_i2c_r(sd, reg);
		break;
	}

	if (ret >= 0)
		sd->sensor_reg_cache[reg] = ret;

	return ret;
}


static void i2c_w_mask(struct sd *sd, u8 reg, u8 value, u8 mask)


{
	int rc;
	u8 oldval;

	value &= mask;			
	rc = i2c_r(sd, reg);
	if (rc < 0)
		return;
	oldval = rc & ~mask;		
	value |= oldval;		
	i2c_w(sd, reg, value);
}


static inline void ov51x_stop(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;

	gspca_dbg(gspca_dev, D_STREAM, "stopping\n");
	sd->stopped = 1;
	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		reg_w(sd, R51x_SYS_RESET, 0x3d);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		reg_w_mask(sd, R51x_SYS_RESET, 0x3a, 0x3a);
		break;
	case BRIDGE_OV519:
		reg_w(sd, OV519_R51_RESET1, 0x0f);
		reg_w(sd, OV519_R51_RESET1, 0x00);
		reg_w(sd, 0x22, 0x00);		
		break;
	case BRIDGE_OVFX2:
		reg_w_mask(sd, 0x0f, 0x00, 0x02);
		break;
	case BRIDGE_W9968CF:
		reg_w(sd, 0x3c, 0x0a05); 
		break;
	}
}


static inline void ov51x_restart(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;

	gspca_dbg(gspca_dev, D_STREAM, "restarting\n");
	if (!sd->stopped)
		return;
	sd->stopped = 0;

	
	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		reg_w(sd, R51x_SYS_RESET, 0x00);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		reg_w(sd, 0x2f, 0x80);
		reg_w(sd, R51x_SYS_RESET, 0x00);
		break;
	case BRIDGE_OV519:
		reg_w(sd, OV519_R51_RESET1, 0x0f);
		reg_w(sd, OV519_R51_RESET1, 0x00);
		reg_w(sd, 0x22, 0x1d);		
		break;
	case BRIDGE_OVFX2:
		reg_w_mask(sd, 0x0f, 0x02, 0x02);
		break;
	case BRIDGE_W9968CF:
		reg_w(sd, 0x3c, 0x8a05); 
		break;
	}
}

static void ov51x_set_slave_ids(struct sd *sd, u8 slave);


static int init_ov_sensor(struct sd *sd, u8 slave)
{
	int i;
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;

	ov51x_set_slave_ids(sd, slave);

	
	i2c_w(sd, 0x12, 0x80);

	
	msleep(150);

	for (i = 0; i < i2c_detect_tries; i++) {
		if (i2c_r(sd, OV7610_REG_ID_HIGH) == 0x7f && i2c_r(sd, OV7610_REG_ID_LOW) == 0xa2) {
			gspca_dbg(gspca_dev, D_PROBE, "I2C synced in %d attempt(s)\n", i);
			return 0;
		}

		
		i2c_w(sd, 0x12, 0x80);

		
		msleep(150);

		
		if (i2c_r(sd, 0x00) < 0)
			return -1;
	}
	return -1;
}


static void ov51x_set_slave_ids(struct sd *sd, u8 slave)
{
	switch (sd->bridge) {
	case BRIDGE_OVFX2:
		reg_w(sd, OVFX2_I2C_ADDR, slave);
		return;
	case BRIDGE_W9968CF:
		sd->sensor_addr = slave;
		return;
	}

	reg_w(sd, R51x_I2C_W_SID, slave);
	reg_w(sd, R51x_I2C_R_SID, slave + 1);
}

static void write_regvals(struct sd *sd, const struct ov_regvals *regvals, int n)

{
	while (--n >= 0) {
		reg_w(sd, regvals->reg, regvals->val);
		regvals++;
	}
}

static void write_i2c_regvals(struct sd *sd, const struct ov_i2c_regvals *regvals, int n)

{
	while (--n >= 0) {
		i2c_w(sd, regvals->reg, regvals->val);
		regvals++;
	}
}




static void ov_hires_configure(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int high, low;

	if (sd->bridge != BRIDGE_OVFX2) {
		gspca_err(gspca_dev, "error hires sensors only supported with ovfx2\n");
		return;
	}

	gspca_dbg(gspca_dev, D_PROBE, "starting ov hires configuration\n");

	
	high = i2c_r(sd, 0x0a);
	low = i2c_r(sd, 0x0b);
	
	switch (high) {
	case 0x96:
		switch (low) {
		case 0x40:
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is a OV2610\n");
			sd->sensor = SEN_OV2610;
			return;
		case 0x41:
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is a OV2610AE\n");
			sd->sensor = SEN_OV2610AE;
			return;
		case 0xb1:
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is a OV9600\n");
			sd->sensor = SEN_OV9600;
			return;
		}
		break;
	case 0x36:
		if ((low & 0x0f) == 0x00) {
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is a OV3610\n");
			sd->sensor = SEN_OV3610;
			return;
		}
		break;
	}
	gspca_err(gspca_dev, "Error unknown sensor type: %02x%02x\n", high, low);
}


static void ov8xx0_configure(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int rc;

	gspca_dbg(gspca_dev, D_PROBE, "starting ov8xx0 configuration\n");

	
	rc = i2c_r(sd, OV7610_REG_COM_I);
	if (rc < 0) {
		gspca_err(gspca_dev, "Error detecting sensor type\n");
		return;
	}
	if ((rc & 3) == 1)
		sd->sensor = SEN_OV8610;
	else gspca_err(gspca_dev, "Unknown image sensor version: %d\n", rc & 3);

}


static void ov7xx0_configure(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int rc, high, low;

	gspca_dbg(gspca_dev, D_PROBE, "starting OV7xx0 configuration\n");

	
	rc = i2c_r(sd, OV7610_REG_COM_I);

	
	if (rc < 0) {
		gspca_err(gspca_dev, "Error detecting sensor type\n");
		return;
	}
	if ((rc & 3) == 3) {
		
		high = i2c_r(sd, 0x0a);
		low = i2c_r(sd, 0x0b);
		
		if (high == 0x76 && (low & 0xf0) == 0x70) {
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV76%02x\n", low);
			sd->sensor = SEN_OV7670;
		} else {
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV7610\n");
			sd->sensor = SEN_OV7610;
		}
	} else if ((rc & 3) == 1) {
		
		if (i2c_r(sd, 0x15) & 1) {
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV7620AE\n");
			sd->sensor = SEN_OV7620AE;
		} else {
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV76BE\n");
			sd->sensor = SEN_OV76BE;
		}
	} else if ((rc & 3) == 0) {
		
		high = i2c_r(sd, 0x0a);
		if (high < 0) {
			gspca_err(gspca_dev, "Error detecting camera chip PID\n");
			return;
		}
		low = i2c_r(sd, 0x0b);
		if (low < 0) {
			gspca_err(gspca_dev, "Error detecting camera chip VER\n");
			return;
		}
		if (high == 0x76) {
			switch (low) {
			case 0x30:
				gspca_err(gspca_dev, "Sensor is an OV7630/OV7635\n");
				gspca_err(gspca_dev, "7630 is not supported by this driver\n");
				return;
			case 0x40:
				gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV7645\n");
				sd->sensor = SEN_OV7640; 
				break;
			case 0x45:
				gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV7645B\n");
				sd->sensor = SEN_OV7640; 
				break;
			case 0x48:
				gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV7648\n");
				sd->sensor = SEN_OV7648;
				break;
			case 0x60:
				gspca_dbg(gspca_dev, D_PROBE, "Sensor is a OV7660\n");
				sd->sensor = SEN_OV7660;
				break;
			default:
				gspca_err(gspca_dev, "Unknown sensor: 0x76%02x\n", low);
				return;
			}
		} else {
			gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV7620\n");
			sd->sensor = SEN_OV7620;
		}
	} else {
		gspca_err(gspca_dev, "Unknown image sensor version: %d\n", rc & 3);
	}
}


static void ov6xx0_configure(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int rc;

	gspca_dbg(gspca_dev, D_PROBE, "starting OV6xx0 configuration\n");

	
	rc = i2c_r(sd, OV7610_REG_COM_I);
	if (rc < 0) {
		gspca_err(gspca_dev, "Error detecting sensor type\n");
		return;
	}

	
	switch (rc) {
	case 0x00:
		sd->sensor = SEN_OV6630;
		pr_warn("WARNING: Sensor is an OV66308. Your camera may have been misdetected in previous driver versions.\n");
		break;
	case 0x01:
		sd->sensor = SEN_OV6620;
		gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV6620\n");
		break;
	case 0x02:
		sd->sensor = SEN_OV6630;
		gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV66308AE\n");
		break;
	case 0x03:
		sd->sensor = SEN_OV66308AF;
		gspca_dbg(gspca_dev, D_PROBE, "Sensor is an OV66308AF\n");
		break;
	case 0x90:
		sd->sensor = SEN_OV6630;
		pr_warn("WARNING: Sensor is an OV66307. Your camera may have been misdetected in previous driver versions.\n");
		break;
	default:
		gspca_err(gspca_dev, "FATAL: Unknown sensor version: 0x%02x\n", rc);
		return;
	}

	
	sd->sif = 1;
}


static void ov51x_led_control(struct sd *sd, int on)
{
	if (sd->invert_led)
		on = !on;

	switch (sd->bridge) {
	
	case BRIDGE_OV511PLUS:
		reg_w(sd, R511_SYS_LED_CTL, on);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		reg_w_mask(sd, R518_GPIO_OUT, 0x02 * on, 0x02);
		break;
	case BRIDGE_OV519:
		reg_w_mask(sd, OV519_GPIO_DATA_OUT0, on, 1);
		break;
	}
}

static void sd_reset_snapshot(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (!sd->snapshot_needs_reset)
		return;

	
	sd->snapshot_needs_reset = 0;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		reg_w(sd, R51x_SYS_SNAP, 0x02);
		reg_w(sd, R51x_SYS_SNAP, 0x00);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		reg_w(sd, R51x_SYS_SNAP, 0x02); 
		reg_w(sd, R51x_SYS_SNAP, 0x01); 
		break;
	case BRIDGE_OV519:
		reg_w(sd, R51x_SYS_RESET, 0x40);
		reg_w(sd, R51x_SYS_RESET, 0x00);
		break;
	}
}

static void ov51x_upload_quan_tables(struct sd *sd)
{
	static const unsigned char yQuanTable511[] = {
		0, 1, 1, 2, 2, 3, 3, 4, 1, 1, 1, 2, 2, 3, 4, 4, 1, 1, 2, 2, 3, 4, 4, 4, 2, 2, 2, 3, 4, 4, 4, 4, 2, 2, 3, 4, 4, 5, 5, 5, 3, 3, 4, 4, 5, 5, 5, 5, 3, 4, 4, 4, 5, 5, 5, 5, 4, 4, 4, 4, 5, 5, 5, 5 };








	static const unsigned char uvQuanTable511[] = {
		0, 2, 2, 3, 4, 4, 4, 4, 2, 2, 2, 4, 4, 4, 4, 4, 2, 2, 3, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };








	
	static const unsigned char yQuanTable518[] = {
		5, 4, 5, 6, 6, 7, 7, 7, 5, 5, 5, 5, 6, 7, 7, 7, 6, 6, 6, 6, 7, 7, 7, 8, 7, 7, 6, 7, 7, 7, 8, 8 };



	static const unsigned char uvQuanTable518[] = {
		6, 6, 6, 7, 7, 7, 7, 7, 6, 6, 6, 7, 7, 7, 7, 7, 6, 6, 6, 7, 7, 7, 7, 8, 7, 7, 7, 7, 7, 7, 8, 8 };




	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	const unsigned char *pYTable, *pUVTable;
	unsigned char val0, val1;
	int i, size, reg = R51x_COMP_LUT_BEGIN;

	gspca_dbg(gspca_dev, D_PROBE, "Uploading quantization tables\n");

	if (sd->bridge == BRIDGE_OV511 || sd->bridge == BRIDGE_OV511PLUS) {
		pYTable = yQuanTable511;
		pUVTable = uvQuanTable511;
		size = 32;
	} else {
		pYTable = yQuanTable518;
		pUVTable = uvQuanTable518;
		size = 16;
	}

	for (i = 0; i < size; i++) {
		val0 = *pYTable++;
		val1 = *pYTable++;
		val0 &= 0x0f;
		val1 &= 0x0f;
		val0 |= val1 << 4;
		reg_w(sd, reg, val0);

		val0 = *pUVTable++;
		val1 = *pUVTable++;
		val0 &= 0x0f;
		val1 &= 0x0f;
		val0 |= val1 << 4;
		reg_w(sd, reg + size, val0);

		reg++;
	}
}


static void ov511_configure(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	
	static const struct ov_regvals init_511[] = {
		{ R51x_SYS_RESET,	0x7f }, { R51x_SYS_INIT,	0x01 }, { R51x_SYS_RESET,	0x7f }, { R51x_SYS_INIT,	0x01 }, { R51x_SYS_RESET,	0x3f }, { R51x_SYS_INIT,	0x01 }, { R51x_SYS_RESET,	0x3d }, };







	static const struct ov_regvals norm_511[] = {
		{ R511_DRAM_FLOW_CTL,	0x01 }, { R51x_SYS_SNAP,	0x00 }, { R51x_SYS_SNAP,	0x02 }, { R51x_SYS_SNAP,	0x00 }, { R511_FIFO_OPTS,	0x1f }, { R511_COMP_EN,		0x00 }, { R511_COMP_LUT_EN,	0x03 }, };







	static const struct ov_regvals norm_511_p[] = {
		{ R511_DRAM_FLOW_CTL,	0xff }, { R51x_SYS_SNAP,	0x00 }, { R51x_SYS_SNAP,	0x02 }, { R51x_SYS_SNAP,	0x00 }, { R511_FIFO_OPTS,	0xff }, { R511_COMP_EN,		0x00 }, { R511_COMP_LUT_EN,	0x03 }, };







	static const struct ov_regvals compress_511[] = {
		{ 0x70, 0x1f }, { 0x71, 0x05 }, { 0x72, 0x06 }, { 0x73, 0x06 }, { 0x74, 0x14 }, { 0x75, 0x03 }, { 0x76, 0x04 }, { 0x77, 0x04 }, };








	gspca_dbg(gspca_dev, D_PROBE, "Device custom id %x\n", reg_r(sd, R51x_SYS_CUST_ID));

	write_regvals(sd, init_511, ARRAY_SIZE(init_511));

	switch (sd->bridge) {
	case BRIDGE_OV511:
		write_regvals(sd, norm_511, ARRAY_SIZE(norm_511));
		break;
	case BRIDGE_OV511PLUS:
		write_regvals(sd, norm_511_p, ARRAY_SIZE(norm_511_p));
		break;
	}

	
	write_regvals(sd, compress_511, ARRAY_SIZE(compress_511));

	ov51x_upload_quan_tables(sd);
}


static void ov518_configure(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	
	static const struct ov_regvals init_518[] = {
		{ R51x_SYS_RESET,	0x40 }, { R51x_SYS_INIT,	0xe1 }, { R51x_SYS_RESET,	0x3e }, { R51x_SYS_INIT,	0xe1 }, { R51x_SYS_RESET,	0x00 }, { R51x_SYS_INIT,	0xe1 }, { 0x46,			0x00 }, { 0x5d,			0x03 }, };








	static const struct ov_regvals norm_518[] = {
		{ R51x_SYS_SNAP,	0x02 },  { R51x_SYS_SNAP,	0x01 }, { 0x31,			0x0f }, { 0x5d,			0x03 }, { 0x24,			0x9f }, { 0x25,			0x90 }, { 0x20,			0x00 }, { 0x51,			0x04 }, { 0x71,			0x19 }, { 0x2f,			0x80 }, };










	static const struct ov_regvals norm_518_p[] = {
		{ R51x_SYS_SNAP,	0x02 },  { R51x_SYS_SNAP,	0x01 }, { 0x31,			0x0f }, { 0x5d,			0x03 }, { 0x24,			0x9f }, { 0x25,			0x90 }, { 0x20,			0x60 }, { 0x51,			0x02 }, { 0x71,			0x19 }, { 0x40,			0xff }, { 0x41,			0x42 }, { 0x46,			0x00 }, { 0x33,			0x04 }, { 0x21,			0x19 }, { 0x3f,			0x10 }, { 0x2f,			0x80 }, };
















	
	sd->revision = reg_r(sd, R51x_SYS_CUST_ID) & 0x1f;
	gspca_dbg(gspca_dev, D_PROBE, "Device revision %d\n", sd->revision);

	write_regvals(sd, init_518, ARRAY_SIZE(init_518));

	
	reg_w_mask(sd, R518_GPIO_CTL, 0x00, 0x02);

	switch (sd->bridge) {
	case BRIDGE_OV518:
		write_regvals(sd, norm_518, ARRAY_SIZE(norm_518));
		break;
	case BRIDGE_OV518PLUS:
		write_regvals(sd, norm_518_p, ARRAY_SIZE(norm_518_p));
		break;
	}

	ov51x_upload_quan_tables(sd);

	reg_w(sd, 0x2f, 0x80);
}

static void ov519_configure(struct sd *sd)
{
	static const struct ov_regvals init_519[] = {
		{ 0x5a, 0x6d },  { 0x53, 0x9b }, { OV519_R54_EN_CLK1, 0xff }, { 0x5d, 0x03 }, { 0x49, 0x01 }, { 0x48, 0x00 },  { OV519_GPIO_IO_CTRL0,   0xee }, { OV519_R51_RESET1, 0x0f }, { OV519_R51_RESET1, 0x00 }, { 0x22, 0x00 },  };












	write_regvals(sd, init_519, ARRAY_SIZE(init_519));
}

static void ovfx2_configure(struct sd *sd)
{
	static const struct ov_regvals init_fx2[] = {
		{ 0x00, 0x60 }, { 0x02, 0x01 }, { 0x0f, 0x1d }, { 0xe9, 0x82 }, { 0xea, 0xc7 }, { 0xeb, 0x10 }, { 0xec, 0xf6 }, };







	sd->stopped = 1;

	write_regvals(sd, init_fx2, ARRAY_SIZE(init_fx2));
}



static void ov519_set_mode(struct sd *sd)
{
	static const struct ov_regvals bridge_ov7660[2][10] = {
		{{0x10, 0x14}, {0x11, 0x1e}, {0x12, 0x00}, {0x13, 0x00}, {0x14, 0x00}, {0x15, 0x00}, {0x16, 0x00}, {0x20, 0x0c}, {0x25, 0x01}, {0x26, 0x00}}, {{0x10, 0x28}, {0x11, 0x3c}, {0x12, 0x00}, {0x13, 0x00}, {0x14, 0x00}, {0x15, 0x00}, {0x16, 0x00}, {0x20, 0x0c}, {0x25, 0x03}, {0x26, 0x00}}




	};
	static const struct ov_i2c_regvals sensor_ov7660[2][3] = {
		{{0x12, 0x00}, {0x24, 0x00}, {0x0c, 0x0c}}, {{0x12, 0x00}, {0x04, 0x00}, {0x0c, 0x00}}
	};
	static const struct ov_i2c_regvals sensor_ov7660_2[] = {
		{OV7670_R17_HSTART, 0x13}, {OV7670_R18_HSTOP, 0x01}, {OV7670_R32_HREF, 0x92}, {OV7670_R19_VSTART, 0x02}, {OV7670_R1A_VSTOP, 0x7a}, {OV7670_R03_VREF, 0x00},     };










	write_regvals(sd, bridge_ov7660[sd->gspca_dev.curr_mode], ARRAY_SIZE(bridge_ov7660[0]));
	write_i2c_regvals(sd, sensor_ov7660[sd->gspca_dev.curr_mode], ARRAY_SIZE(sensor_ov7660[0]));
	write_i2c_regvals(sd, sensor_ov7660_2, ARRAY_SIZE(sensor_ov7660_2));
}



static void ov519_set_fr(struct sd *sd)
{
	int fr;
	u8 clock;
	
	static const u8 fr_tb[2][6][3] = {
		{{0x04, 0xff, 0x00}, {0x04, 0x1f, 0x00}, {0x04, 0x1b, 0x00}, {0x04, 0x15, 0x00}, {0x04, 0x09, 0x00}, {0x04, 0x01, 0x00}}, {{0x0c, 0xff, 0x00}, {0x0c, 0x1f, 0x00}, {0x0c, 0x1b, 0x00}, {0x04, 0xff, 0x01}, {0x04, 0x1f, 0x01}, {0x04, 0x1b, 0x01}}, };












	if (frame_rate > 0)
		sd->frame_rate = frame_rate;
	if (sd->frame_rate >= 30)
		fr = 0;
	else if (sd->frame_rate >= 25)
		fr = 1;
	else if (sd->frame_rate >= 20)
		fr = 2;
	else if (sd->frame_rate >= 15)
		fr = 3;
	else if (sd->frame_rate >= 10)
		fr = 4;
	else fr = 5;
	reg_w(sd, 0xa4, fr_tb[sd->gspca_dev.curr_mode][fr][0]);
	reg_w(sd, 0x23, fr_tb[sd->gspca_dev.curr_mode][fr][1]);
	clock = fr_tb[sd->gspca_dev.curr_mode][fr][2];
	if (sd->sensor == SEN_OV7660)
		clock |= 0x80;		
	ov518_i2c_w(sd, OV7670_R11_CLKRC, clock);
}

static void setautogain(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	i2c_w_mask(sd, 0x13, val ? 0x05 : 0x00, 0x05);
}


static int sd_config(struct gspca_dev *gspca_dev, const struct usb_device_id *id)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct cam *cam = &gspca_dev->cam;

	sd->bridge = id->driver_info & BRIDGE_MASK;
	sd->invert_led = (id->driver_info & BRIDGE_INVERT_LED) != 0;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		cam->cam_mode = ov511_vga_mode;
		cam->nmodes = ARRAY_SIZE(ov511_vga_mode);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		cam->cam_mode = ov518_vga_mode;
		cam->nmodes = ARRAY_SIZE(ov518_vga_mode);
		break;
	case BRIDGE_OV519:
		cam->cam_mode = ov519_vga_mode;
		cam->nmodes = ARRAY_SIZE(ov519_vga_mode);
		break;
	case BRIDGE_OVFX2:
		cam->cam_mode = ov519_vga_mode;
		cam->nmodes = ARRAY_SIZE(ov519_vga_mode);
		cam->bulk_size = OVFX2_BULK_SIZE;
		cam->bulk_nurbs = MAX_NURBS;
		cam->bulk = 1;
		break;
	case BRIDGE_W9968CF:
		cam->cam_mode = w9968cf_vga_mode;
		cam->nmodes = ARRAY_SIZE(w9968cf_vga_mode);
		break;
	}

	sd->frame_rate = 15;

	return 0;
}


static int sd_init(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;
	struct cam *cam = &gspca_dev->cam;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		ov511_configure(gspca_dev);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		ov518_configure(gspca_dev);
		break;
	case BRIDGE_OV519:
		ov519_configure(sd);
		break;
	case BRIDGE_OVFX2:
		ovfx2_configure(sd);
		break;
	case BRIDGE_W9968CF:
		w9968cf_configure(sd);
		break;
	}

	
	sd->sensor = -1;

	
	if (init_ov_sensor(sd, OV7xx0_SID) >= 0) {
		ov7xx0_configure(sd);

	
	} else if (init_ov_sensor(sd, OV6xx0_SID) >= 0) {
		ov6xx0_configure(sd);

	
	} else if (init_ov_sensor(sd, OV8xx0_SID) >= 0) {
		ov8xx0_configure(sd);

	
	} else if (init_ov_sensor(sd, OV_HIRES_SID) >= 0) {
		ov_hires_configure(sd);
	} else {
		gspca_err(gspca_dev, "Can't determine sensor slave IDs\n");
		goto error;
	}

	if (sd->sensor < 0)
		goto error;

	ov51x_led_control(sd, 0);	

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		if (sd->sif) {
			cam->cam_mode = ov511_sif_mode;
			cam->nmodes = ARRAY_SIZE(ov511_sif_mode);
		}
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		if (sd->sif) {
			cam->cam_mode = ov518_sif_mode;
			cam->nmodes = ARRAY_SIZE(ov518_sif_mode);
		}
		break;
	case BRIDGE_OV519:
		if (sd->sif) {
			cam->cam_mode = ov519_sif_mode;
			cam->nmodes = ARRAY_SIZE(ov519_sif_mode);
		}
		break;
	case BRIDGE_OVFX2:
		switch (sd->sensor) {
		case SEN_OV2610:
		case SEN_OV2610AE:
			cam->cam_mode = ovfx2_ov2610_mode;
			cam->nmodes = ARRAY_SIZE(ovfx2_ov2610_mode);
			break;
		case SEN_OV3610:
			cam->cam_mode = ovfx2_ov3610_mode;
			cam->nmodes = ARRAY_SIZE(ovfx2_ov3610_mode);
			break;
		case SEN_OV9600:
			cam->cam_mode = ovfx2_ov9600_mode;
			cam->nmodes = ARRAY_SIZE(ovfx2_ov9600_mode);
			break;
		default:
			if (sd->sif) {
				cam->cam_mode = ov519_sif_mode;
				cam->nmodes = ARRAY_SIZE(ov519_sif_mode);
			}
			break;
		}
		break;
	case BRIDGE_W9968CF:
		if (sd->sif)
			cam->nmodes = ARRAY_SIZE(w9968cf_vga_mode) - 1;

		
		w9968cf_init(sd);
		break;
	}

	
	switch (sd->sensor) {
	case SEN_OV2610:
		write_i2c_regvals(sd, norm_2610, ARRAY_SIZE(norm_2610));

		
		i2c_w_mask(sd, 0x13, 0x27, 0x27);
		break;
	case SEN_OV2610AE:
		write_i2c_regvals(sd, norm_2610ae, ARRAY_SIZE(norm_2610ae));

		
		i2c_w_mask(sd, 0x13, 0x05, 0x05);
		break;
	case SEN_OV3610:
		write_i2c_regvals(sd, norm_3620b, ARRAY_SIZE(norm_3620b));

		
		i2c_w_mask(sd, 0x13, 0x27, 0x27);
		break;
	case SEN_OV6620:
		write_i2c_regvals(sd, norm_6x20, ARRAY_SIZE(norm_6x20));
		break;
	case SEN_OV6630:
	case SEN_OV66308AF:
		write_i2c_regvals(sd, norm_6x30, ARRAY_SIZE(norm_6x30));
		break;
	default:


		write_i2c_regvals(sd, norm_7610, ARRAY_SIZE(norm_7610));
		i2c_w_mask(sd, 0x0e, 0x00, 0x40);
		break;
	case SEN_OV7620:
	case SEN_OV7620AE:
		write_i2c_regvals(sd, norm_7620, ARRAY_SIZE(norm_7620));
		break;
	case SEN_OV7640:
	case SEN_OV7648:
		write_i2c_regvals(sd, norm_7640, ARRAY_SIZE(norm_7640));
		break;
	case SEN_OV7660:
		i2c_w(sd, OV7670_R12_COM7, OV7670_COM7_RESET);
		msleep(14);
		reg_w(sd, OV519_R57_SNAPSHOT, 0x23);
		write_regvals(sd, init_519_ov7660, ARRAY_SIZE(init_519_ov7660));
		write_i2c_regvals(sd, norm_7660, ARRAY_SIZE(norm_7660));
		sd->gspca_dev.curr_mode = 1;	
		ov519_set_mode(sd);
		ov519_set_fr(sd);
		sd_reset_snapshot(gspca_dev);
		ov51x_restart(sd);
		ov51x_stop(sd);			
		ov51x_led_control(sd, 0);
		break;
	case SEN_OV7670:
		write_i2c_regvals(sd, norm_7670, ARRAY_SIZE(norm_7670));
		break;
	case SEN_OV8610:
		write_i2c_regvals(sd, norm_8610, ARRAY_SIZE(norm_8610));
		break;
	case SEN_OV9600:
		write_i2c_regvals(sd, norm_9600, ARRAY_SIZE(norm_9600));

		

		break;
	}
	return gspca_dev->usb_err;
error:
	gspca_err(gspca_dev, "OV519 Config failed\n");
	return -EINVAL;
}


static int sd_isoc_init(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	switch (sd->bridge) {
	case BRIDGE_OVFX2:
		if (gspca_dev->pixfmt.width != 800)
			gspca_dev->cam.bulk_size = OVFX2_BULK_SIZE;
		else gspca_dev->cam.bulk_size = 7 * 4096;
		break;
	}
	return 0;
}


static void ov511_mode_init_regs(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int hsegs, vsegs, packet_size, fps, needed;
	int interlaced = 0;
	struct usb_host_interface *alt;
	struct usb_interface *intf;

	intf = usb_ifnum_to_if(sd->gspca_dev.dev, sd->gspca_dev.iface);
	alt = usb_altnum_to_altsetting(intf, sd->gspca_dev.alt);
	if (!alt) {
		gspca_err(gspca_dev, "Couldn't get altsetting\n");
		sd->gspca_dev.usb_err = -EIO;
		return;
	}

	packet_size = le16_to_cpu(alt->endpoint[0].desc.wMaxPacketSize);
	reg_w(sd, R51x_FIFO_PSIZE, packet_size >> 5);

	reg_w(sd, R511_CAM_UV_EN, 0x01);
	reg_w(sd, R511_SNAP_UV_EN, 0x01);
	reg_w(sd, R511_SNAP_OPTS, 0x03);

	
	hsegs = (sd->gspca_dev.pixfmt.width >> 3) - 1;
	vsegs = (sd->gspca_dev.pixfmt.height >> 3) - 1;

	reg_w(sd, R511_CAM_PXCNT, hsegs);
	reg_w(sd, R511_CAM_LNCNT, vsegs);
	reg_w(sd, R511_CAM_PXDIV, 0x00);
	reg_w(sd, R511_CAM_LNDIV, 0x00);

	
	reg_w(sd, R511_CAM_OPTS, 0x03);

	
	reg_w(sd, R511_SNAP_PXCNT, hsegs);
	reg_w(sd, R511_SNAP_LNCNT, vsegs);
	reg_w(sd, R511_SNAP_PXDIV, 0x00);
	reg_w(sd, R511_SNAP_LNDIV, 0x00);

	
	if (frame_rate > 0)
		sd->frame_rate = frame_rate;

	switch (sd->sensor) {
	case SEN_OV6620:
		
		sd->clockdiv = 3;
		break;

	
	case SEN_OV7620:
	case SEN_OV7620AE:
	case SEN_OV7640:
	case SEN_OV7648:
	case SEN_OV76BE:
		if (sd->gspca_dev.pixfmt.width == 320)
			interlaced = 1;
		
	case SEN_OV6630:
	case SEN_OV7610:
	case SEN_OV7670:
		switch (sd->frame_rate) {
		case 30:
		case 25:
			
			if (sd->gspca_dev.pixfmt.width != 640) {
				sd->clockdiv = 0;
				break;
			}
			
			
		default:


			sd->clockdiv = 1;
			break;
		case 10:
			sd->clockdiv = 2;
			break;
		case 5:
			sd->clockdiv = 5;
			break;
		}
		if (interlaced) {
			sd->clockdiv = (sd->clockdiv + 1) * 2 - 1;
			
			if (sd->clockdiv > 10)
				sd->clockdiv = 10;
		}
		break;

	case SEN_OV8610:
		
		sd->clockdiv = 0;
		break;
	}

	
	fps = (interlaced ? 60 : 30) / (sd->clockdiv + 1) + 1;
	needed = fps * sd->gspca_dev.pixfmt.width * sd->gspca_dev.pixfmt.height * 3 / 2;
	
	if (needed > 1000 * packet_size) {
		
		reg_w(sd, R511_COMP_EN, 0x07);
		reg_w(sd, R511_COMP_LUT_EN, 0x03);
	} else {
		reg_w(sd, R511_COMP_EN, 0x06);
		reg_w(sd, R511_COMP_LUT_EN, 0x00);
	}

	reg_w(sd, R51x_SYS_RESET, OV511_RESET_OMNICE);
	reg_w(sd, R51x_SYS_RESET, 0);
}


static void ov518_mode_init_regs(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int hsegs, vsegs, packet_size;
	struct usb_host_interface *alt;
	struct usb_interface *intf;

	intf = usb_ifnum_to_if(sd->gspca_dev.dev, sd->gspca_dev.iface);
	alt = usb_altnum_to_altsetting(intf, sd->gspca_dev.alt);
	if (!alt) {
		gspca_err(gspca_dev, "Couldn't get altsetting\n");
		sd->gspca_dev.usb_err = -EIO;
		return;
	}

	packet_size = le16_to_cpu(alt->endpoint[0].desc.wMaxPacketSize);
	ov518_reg_w32(sd, R51x_FIFO_PSIZE, packet_size & ~7, 2);

	
	reg_w(sd, 0x2b, 0);
	reg_w(sd, 0x2c, 0);
	reg_w(sd, 0x2d, 0);
	reg_w(sd, 0x2e, 0);
	reg_w(sd, 0x3b, 0);
	reg_w(sd, 0x3c, 0);
	reg_w(sd, 0x3d, 0);
	reg_w(sd, 0x3e, 0);

	if (sd->bridge == BRIDGE_OV518) {
		
		reg_w_mask(sd, 0x20, 0x08, 0x08);

		
		reg_w_mask(sd, 0x28, 0x80, 0xf0);
		reg_w_mask(sd, 0x38, 0x80, 0xf0);
	} else {
		reg_w(sd, 0x28, 0x80);
		reg_w(sd, 0x38, 0x80);
	}

	hsegs = sd->gspca_dev.pixfmt.width / 16;
	vsegs = sd->gspca_dev.pixfmt.height / 4;

	reg_w(sd, 0x29, hsegs);
	reg_w(sd, 0x2a, vsegs);

	reg_w(sd, 0x39, hsegs);
	reg_w(sd, 0x3a, vsegs);

	
	reg_w(sd, 0x2f, 0x80);

	
	if (sd->bridge == BRIDGE_OV518PLUS && sd->revision == 0 && sd->sensor == SEN_OV7620AE)
		sd->clockdiv = 0;
	else sd->clockdiv = 1;

	
	
	reg_w(sd, 0x51, 0x04);
	reg_w(sd, 0x22, 0x18);
	reg_w(sd, 0x23, 0xff);

	if (sd->bridge == BRIDGE_OV518PLUS) {
		switch (sd->sensor) {
		case SEN_OV7620AE:
			
			if (sd->revision > 0 && sd->gspca_dev.pixfmt.width == 640) {
				reg_w(sd, 0x20, 0x60);
				reg_w(sd, 0x21, 0x1f);
			} else {
				reg_w(sd, 0x20, 0x00);
				reg_w(sd, 0x21, 0x19);
			}
			break;
		case SEN_OV7620:
			reg_w(sd, 0x20, 0x00);
			reg_w(sd, 0x21, 0x19);
			break;
		default:
			reg_w(sd, 0x21, 0x19);
		}
	} else reg_w(sd, 0x71, 0x17);

	
	
	i2c_w(sd, 0x54, 0x23);

	reg_w(sd, 0x2f, 0x80);

	if (sd->bridge == BRIDGE_OV518PLUS) {
		reg_w(sd, 0x24, 0x94);
		reg_w(sd, 0x25, 0x90);
		ov518_reg_w32(sd, 0xc4,    400, 2);	
		ov518_reg_w32(sd, 0xc6,    540, 2);	
		ov518_reg_w32(sd, 0xc7,    540, 2);	
		ov518_reg_w32(sd, 0xc8,    108, 2);	
		ov518_reg_w32(sd, 0xca, 131098, 3);	
		ov518_reg_w32(sd, 0xcb,    532, 2);	
		ov518_reg_w32(sd, 0xcc,   2400, 2);	
		ov518_reg_w32(sd, 0xcd,     32, 2);	
		ov518_reg_w32(sd, 0xce,    608, 2);	
	} else {
		reg_w(sd, 0x24, 0x9f);
		reg_w(sd, 0x25, 0x90);
		ov518_reg_w32(sd, 0xc4,    400, 2);	
		ov518_reg_w32(sd, 0xc6,    381, 2);	
		ov518_reg_w32(sd, 0xc7,    381, 2);	
		ov518_reg_w32(sd, 0xc8,    128, 2);	
		ov518_reg_w32(sd, 0xca, 183331, 3);	
		ov518_reg_w32(sd, 0xcb,    746, 2);	
		ov518_reg_w32(sd, 0xcc,   1750, 2);	
		ov518_reg_w32(sd, 0xcd,     45, 2);	
		ov518_reg_w32(sd, 0xce,    851, 2);	
	}

	reg_w(sd, 0x2f, 0x80);
}


static void ov519_mode_init_regs(struct sd *sd)
{
	static const struct ov_regvals mode_init_519_ov7670[] = {
		{ 0x5d,	0x03 },  { 0x53,	0x9f }, { OV519_R54_EN_CLK1, 0x0f }, { 0xa2,	0x20 }, { 0xa3,	0x18 }, { 0xa4,	0x04 }, { 0xa5,	0x28 }, { 0x37,	0x00 }, { 0x55,	0x02 },  { 0x20,	0x0c }, { 0x21,	0x38 }, { 0x22,	0x1d }, { 0x17,	0x50 }, { 0x37,	0x00 }, { 0x40,	0xff }, { 0x46,	0x00 }, { 0x59,	0x04 }, { 0xff,	0x00 },  };




















	static const struct ov_regvals mode_init_519[] = {
		{ 0x5d,	0x03 },  { 0x53,	0x9f }, { OV519_R54_EN_CLK1, 0x0f }, { 0xa2,	0x20 }, { 0xa3,	0x18 }, { 0xa4,	0x04 }, { 0xa5,	0x28 }, { 0x37,	0x00 }, { 0x55,	0x02 },  { 0x22,	0x1d }, { 0x17,	0x50 }, { 0x37,	0x00 }, { 0x40,	0xff }, { 0x46,	0x00 }, { 0x59,	0x04 }, { 0xff,	0x00 },  };


















	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;

	
	switch (sd->sensor) {
	default:
		write_regvals(sd, mode_init_519, ARRAY_SIZE(mode_init_519));
		if (sd->sensor == SEN_OV7640 || sd->sensor == SEN_OV7648) {
			
			reg_w_mask(sd, OV519_R20_DFR, 0x10, 0x10);
		}
		break;
	case SEN_OV7660:
		return;		
	case SEN_OV7670:
		write_regvals(sd, mode_init_519_ov7670, ARRAY_SIZE(mode_init_519_ov7670));
		break;
	}

	reg_w(sd, OV519_R10_H_SIZE,	sd->gspca_dev.pixfmt.width >> 4);
	reg_w(sd, OV519_R11_V_SIZE,	sd->gspca_dev.pixfmt.height >> 3);
	if (sd->sensor == SEN_OV7670 && sd->gspca_dev.cam.cam_mode[sd->gspca_dev.curr_mode].priv)
		reg_w(sd, OV519_R12_X_OFFSETL, 0x04);
	else if (sd->sensor == SEN_OV7648 && sd->gspca_dev.cam.cam_mode[sd->gspca_dev.curr_mode].priv)
		reg_w(sd, OV519_R12_X_OFFSETL, 0x01);
	else reg_w(sd, OV519_R12_X_OFFSETL, 0x00);
	reg_w(sd, OV519_R13_X_OFFSETH,	0x00);
	reg_w(sd, OV519_R14_Y_OFFSETL,	0x00);
	reg_w(sd, OV519_R15_Y_OFFSETH,	0x00);
	reg_w(sd, OV519_R16_DIVIDER,	0x00);
	reg_w(sd, OV519_R25_FORMAT,	0x03); 
	reg_w(sd, 0x26,			0x00); 

	
	if (frame_rate > 0)
		sd->frame_rate = frame_rate;


	sd->clockdiv = 0;
	switch (sd->sensor) {
	case SEN_OV7640:
	case SEN_OV7648:
		switch (sd->frame_rate) {
		default:

			reg_w(sd, 0xa4, 0x0c);
			reg_w(sd, 0x23, 0xff);
			break;
		case 25:
			reg_w(sd, 0xa4, 0x0c);
			reg_w(sd, 0x23, 0x1f);
			break;
		case 20:
			reg_w(sd, 0xa4, 0x0c);
			reg_w(sd, 0x23, 0x1b);
			break;
		case 15:
			reg_w(sd, 0xa4, 0x04);
			reg_w(sd, 0x23, 0xff);
			sd->clockdiv = 1;
			break;
		case 10:
			reg_w(sd, 0xa4, 0x04);
			reg_w(sd, 0x23, 0x1f);
			sd->clockdiv = 1;
			break;
		case 5:
			reg_w(sd, 0xa4, 0x04);
			reg_w(sd, 0x23, 0x1b);
			sd->clockdiv = 1;
			break;
		}
		break;
	case SEN_OV8610:
		switch (sd->frame_rate) {
		default:	

			reg_w(sd, 0xa4, 0x06);
			reg_w(sd, 0x23, 0xff);
			break;
		case 10:
			reg_w(sd, 0xa4, 0x06);
			reg_w(sd, 0x23, 0x1f);
			break;
		case 5:
			reg_w(sd, 0xa4, 0x06);
			reg_w(sd, 0x23, 0x1b);
			break;
		}
		break;
	case SEN_OV7670:		
		gspca_dbg(gspca_dev, D_STREAM, "Setting framerate to %d fps\n", (sd->frame_rate == 0) ? 15 : sd->frame_rate);
		reg_w(sd, 0xa4, 0x10);
		switch (sd->frame_rate) {
		case 30:
			reg_w(sd, 0x23, 0xff);
			break;
		case 20:
			reg_w(sd, 0x23, 0x1b);
			break;
		default:

			reg_w(sd, 0x23, 0xff);
			sd->clockdiv = 1;
			break;
		}
		break;
	}
}

static void mode_init_ov_sensor_regs(struct sd *sd)
{
	struct gspca_dev *gspca_dev = (struct gspca_dev *)sd;
	int qvga, xstart, xend, ystart, yend;
	u8 v;

	qvga = gspca_dev->cam.cam_mode[gspca_dev->curr_mode].priv & 1;

	
	switch (sd->sensor) {
	case SEN_OV2610:
		i2c_w_mask(sd, 0x14, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x28, qvga ? 0x00 : 0x20, 0x20);
		i2c_w(sd, 0x24, qvga ? 0x20 : 0x3a);
		i2c_w(sd, 0x25, qvga ? 0x30 : 0x60);
		i2c_w_mask(sd, 0x2d, qvga ? 0x40 : 0x00, 0x40);
		i2c_w_mask(sd, 0x67, qvga ? 0xf0 : 0x90, 0xf0);
		i2c_w_mask(sd, 0x74, qvga ? 0x20 : 0x00, 0x20);
		return;
	case SEN_OV2610AE: {
		u8 v;

		
		v = 80;
		if (qvga) {
			if (sd->frame_rate < 25)
				v = 0x81;
		} else {
			if (sd->frame_rate < 10)
				v = 0x81;
		}
		i2c_w(sd, 0x11, v);
		i2c_w(sd, 0x12, qvga ? 0x60 : 0x20);
		return;
	    }
	case SEN_OV3610:
		if (qvga) {
			xstart = (1040 - gspca_dev->pixfmt.width) / 2 + (0x1f << 4);
			ystart = (776 - gspca_dev->pixfmt.height) / 2;
		} else {
			xstart = (2076 - gspca_dev->pixfmt.width) / 2 + (0x10 << 4);
			ystart = (1544 - gspca_dev->pixfmt.height) / 2;
		}
		xend = xstart + gspca_dev->pixfmt.width;
		yend = ystart + gspca_dev->pixfmt.height;
		
		i2c_w_mask(sd, 0x12, qvga ? 0x40 : 0x00, 0xf0);
		i2c_w_mask(sd, 0x32, (((xend >> 1) & 7) << 3) | ((xstart >> 1) & 7), 0x3f);

		i2c_w_mask(sd, 0x03, (((yend >> 1) & 3) << 2) | ((ystart >> 1) & 3), 0x0f);

		i2c_w(sd, 0x17, xstart >> 4);
		i2c_w(sd, 0x18, xend >> 4);
		i2c_w(sd, 0x19, ystart >> 3);
		i2c_w(sd, 0x1a, yend >> 3);
		return;
	case SEN_OV8610:
		
		i2c_w_mask(sd, OV7610_REG_COM_C, qvga ? (1 << 5) : 0, 1 << 5);
		i2c_w_mask(sd, 0x13, 0x00, 0x20); 
		i2c_w_mask(sd, 0x12, 0x04, 0x06); 
		i2c_w_mask(sd, 0x2d, 0x00, 0x40); 
		i2c_w_mask(sd, 0x28, 0x20, 0x20); 
		break;
	case SEN_OV7610:
		i2c_w_mask(sd, 0x14, qvga ? 0x20 : 0x00, 0x20);
		i2c_w(sd, 0x35, qvga ? 0x1e : 0x9e);
		i2c_w_mask(sd, 0x13, 0x00, 0x20); 
		i2c_w_mask(sd, 0x12, 0x04, 0x06); 
		break;
	case SEN_OV7620:
	case SEN_OV7620AE:
	case SEN_OV76BE:
		i2c_w_mask(sd, 0x14, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x28, qvga ? 0x00 : 0x20, 0x20);
		i2c_w(sd, 0x24, qvga ? 0x20 : 0x3a);
		i2c_w(sd, 0x25, qvga ? 0x30 : 0x60);
		i2c_w_mask(sd, 0x2d, qvga ? 0x40 : 0x00, 0x40);
		i2c_w_mask(sd, 0x67, qvga ? 0xb0 : 0x90, 0xf0);
		i2c_w_mask(sd, 0x74, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x13, 0x00, 0x20); 
		i2c_w_mask(sd, 0x12, 0x04, 0x06); 
		if (sd->sensor == SEN_OV76BE)
			i2c_w(sd, 0x35, qvga ? 0x1e : 0x9e);
		break;
	case SEN_OV7640:
	case SEN_OV7648:
		i2c_w_mask(sd, 0x14, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x28, qvga ? 0x00 : 0x20, 0x20);
		
		i2c_w_mask(sd, 0x2d, qvga ? 0x40 : 0x00, 0x40);
		
		i2c_w_mask(sd, 0x67, qvga ? 0xf0 : 0x90, 0xf0);
		
		i2c_w_mask(sd, 0x74, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x12, 0x04, 0x04); 
		break;
	case SEN_OV7670:
		
		i2c_w_mask(sd, OV7670_R12_COM7, qvga ? OV7670_COM7_FMT_QVGA : OV7670_COM7_FMT_VGA, OV7670_COM7_FMT_MASK);

		i2c_w_mask(sd, 0x13, 0x00, 0x20); 
		i2c_w_mask(sd, OV7670_R13_COM8, OV7670_COM8_AWB, OV7670_COM8_AWB);
		if (qvga) {		
			xstart = 164;
			xend = 28;
			ystart = 14;
			yend = 494;
		} else {		
			xstart = 158;
			xend = 14;
			ystart = 10;
			yend = 490;
		}
		
		i2c_w(sd, OV7670_R17_HSTART, xstart >> 3);
		i2c_w(sd, OV7670_R18_HSTOP, xend >> 3);
		v = i2c_r(sd, OV7670_R32_HREF);
		v = (v & 0xc0) | ((xend & 0x7) << 3) | (xstart & 0x07);
		msleep(10);	
		i2c_w(sd, OV7670_R32_HREF, v);

		i2c_w(sd, OV7670_R19_VSTART, ystart >> 2);
		i2c_w(sd, OV7670_R1A_VSTOP, yend >> 2);
		v = i2c_r(sd, OV7670_R03_VREF);
		v = (v & 0xc0) | ((yend & 0x3) << 2) | (ystart & 0x03);
		msleep(10);	
		i2c_w(sd, OV7670_R03_VREF, v);
		break;
	case SEN_OV6620:
		i2c_w_mask(sd, 0x14, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x13, 0x00, 0x20); 
		i2c_w_mask(sd, 0x12, 0x04, 0x06); 
		break;
	case SEN_OV6630:
	case SEN_OV66308AF:
		i2c_w_mask(sd, 0x14, qvga ? 0x20 : 0x00, 0x20);
		i2c_w_mask(sd, 0x12, 0x04, 0x06); 
		break;
	case SEN_OV9600: {
		const struct ov_i2c_regvals *vals;
		static const struct ov_i2c_regvals sxga_15[] = {
			{0x11, 0x80}, {0x14, 0x3e}, {0x24, 0x85}, {0x25, 0x75}
		};
		static const struct ov_i2c_regvals sxga_7_5[] = {
			{0x11, 0x81}, {0x14, 0x3e}, {0x24, 0x85}, {0x25, 0x75}
		};
		static const struct ov_i2c_regvals vga_30[] = {
			{0x11, 0x81}, {0x14, 0x7e}, {0x24, 0x70}, {0x25, 0x60}
		};
		static const struct ov_i2c_regvals vga_15[] = {
			{0x11, 0x83}, {0x14, 0x3e}, {0x24, 0x80}, {0x25, 0x70}
		};

		
		i2c_w_mask(sd, 0x12, qvga ? 0x40 : 0x00, 0x40);
		if (qvga)
			vals = sd->frame_rate < 30 ? vga_15 : vga_30;
		else vals = sd->frame_rate < 15 ? sxga_7_5 : sxga_15;
		write_i2c_regvals(sd, vals, ARRAY_SIZE(sxga_15));
		return;
	    }
	default:
		return;
	}

	
	i2c_w(sd, 0x11, sd->clockdiv);
}


static void sethvflip(struct gspca_dev *gspca_dev, s32 hflip, s32 vflip)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (sd->gspca_dev.streaming)
		reg_w(sd, OV519_R51_RESET1, 0x0f);	
	i2c_w_mask(sd, OV7670_R1E_MVFP, OV7670_MVFP_MIRROR * hflip | OV7670_MVFP_VFLIP * vflip, OV7670_MVFP_MIRROR | OV7670_MVFP_VFLIP);

	if (sd->gspca_dev.streaming)
		reg_w(sd, OV519_R51_RESET1, 0x00);	
}

static void set_ov_sensor_window(struct sd *sd)
{
	struct gspca_dev *gspca_dev;
	int qvga, crop;
	int hwsbase, hwebase, vwsbase, vwebase, hwscale, vwscale;

	
	switch (sd->sensor) {
	case SEN_OV2610:
	case SEN_OV2610AE:
	case SEN_OV3610:
	case SEN_OV7670:
	case SEN_OV9600:
		mode_init_ov_sensor_regs(sd);
		return;
	case SEN_OV7660:
		ov519_set_mode(sd);
		ov519_set_fr(sd);
		return;
	}

	gspca_dev = &sd->gspca_dev;
	qvga = gspca_dev->cam.cam_mode[gspca_dev->curr_mode].priv & 1;
	crop = gspca_dev->cam.cam_mode[gspca_dev->curr_mode].priv & 2;

	
	switch (sd->sensor) {
	case SEN_OV8610:
		hwsbase = 0x1e;
		hwebase = 0x1e;
		vwsbase = 0x02;
		vwebase = 0x02;
		break;
	case SEN_OV7610:
	case SEN_OV76BE:
		hwsbase = 0x38;
		hwebase = 0x3a;
		vwsbase = vwebase = 0x05;
		break;
	case SEN_OV6620:
	case SEN_OV6630:
	case SEN_OV66308AF:
		hwsbase = 0x38;
		hwebase = 0x3a;
		vwsbase = 0x05;
		vwebase = 0x06;
		if (sd->sensor == SEN_OV66308AF && qvga)
			
			hwsbase++;
		if (crop) {
			hwsbase += 8;
			hwebase += 8;
			vwsbase += 11;
			vwebase += 11;
		}
		break;
	case SEN_OV7620:
	case SEN_OV7620AE:
		hwsbase = 0x2f;		
		hwebase = 0x2f;
		vwsbase = vwebase = 0x05;
		break;
	case SEN_OV7640:
	case SEN_OV7648:
		hwsbase = 0x1a;
		hwebase = 0x1a;
		vwsbase = vwebase = 0x03;
		break;
	default:
		return;
	}

	switch (sd->sensor) {
	case SEN_OV6620:
	case SEN_OV6630:
	case SEN_OV66308AF:
		if (qvga) {		
			hwscale = 0;
			vwscale = 0;
		} else {		
			hwscale = 1;
			vwscale = 1;	
		}
		break;
	case SEN_OV8610:
		if (qvga) {		
			hwscale = 1;
			vwscale = 1;
		} else {		
			hwscale = 2;
			vwscale = 2;
		}
		break;
	default:			
		if (qvga) {		
			hwscale = 1;
			vwscale = 0;
		} else {		
			hwscale = 2;
			vwscale = 1;
		}
	}

	mode_init_ov_sensor_regs(sd);

	i2c_w(sd, 0x17, hwsbase);
	i2c_w(sd, 0x18, hwebase + (sd->sensor_width >> hwscale));
	i2c_w(sd, 0x19, vwsbase);
	i2c_w(sd, 0x1a, vwebase + (sd->sensor_height >> vwscale));
}


static int sd_start(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	
	sd->sensor_width = sd->gspca_dev.pixfmt.width;
	sd->sensor_height = sd->gspca_dev.pixfmt.height;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		ov511_mode_init_regs(sd);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		ov518_mode_init_regs(sd);
		break;
	case BRIDGE_OV519:
		ov519_mode_init_regs(sd);
		break;
	
	case BRIDGE_W9968CF:
		w9968cf_mode_init_regs(sd);
		break;
	}

	set_ov_sensor_window(sd);

	
	sd->snapshot_needs_reset = 1;
	sd_reset_snapshot(gspca_dev);

	sd->first_frame = 3;

	ov51x_restart(sd);
	ov51x_led_control(sd, 1);
	return gspca_dev->usb_err;
}

static void sd_stopN(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	ov51x_stop(sd);
	ov51x_led_control(sd, 0);
}

static void sd_stop0(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (!sd->gspca_dev.present)
		return;
	if (sd->bridge == BRIDGE_W9968CF)
		w9968cf_stop0(sd);


	
	if (sd->snapshot_pressed) {
		input_report_key(gspca_dev->input_dev, KEY_CAMERA, 0);
		input_sync(gspca_dev->input_dev);
		sd->snapshot_pressed = 0;
	}

	if (sd->bridge == BRIDGE_OV519)
		reg_w(sd, OV519_R57_SNAPSHOT, 0x23);
}

static void ov51x_handle_button(struct gspca_dev *gspca_dev, u8 state)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (sd->snapshot_pressed != state) {

		input_report_key(gspca_dev->input_dev, KEY_CAMERA, state);
		input_sync(gspca_dev->input_dev);

		if (state)
			sd->snapshot_needs_reset = 1;

		sd->snapshot_pressed = state;
	} else {
		
		switch (sd->bridge) {
		case BRIDGE_OV511:
		case BRIDGE_OV511PLUS:
		case BRIDGE_OV519:
			if (state)
				sd->snapshot_needs_reset = 1;
			break;
		}
	}
}

static void ov511_pkt_scan(struct gspca_dev *gspca_dev, u8 *in, int len)

{
	struct sd *sd = (struct sd *) gspca_dev;

	
	if (!(in[0] | in[1] | in[2] | in[3] | in[4] | in[5] | in[6] | in[7]) && (in[8] & 0x08)) {
		ov51x_handle_button(gspca_dev, (in[8] >> 2) & 1);
		if (in[8] & 0x80) {
			
			if ((in[9] + 1) * 8 != gspca_dev->pixfmt.width || (in[10] + 1) * 8 != gspca_dev->pixfmt.height) {
				gspca_err(gspca_dev, "Invalid frame size, got: %dx%d, requested: %dx%d\n", (in[9] + 1) * 8, (in[10] + 1) * 8, gspca_dev->pixfmt.width, gspca_dev->pixfmt.height);


				gspca_dev->last_packet_type = DISCARD_PACKET;
				return;
			}
			
			gspca_frame_add(gspca_dev, LAST_PACKET, in, 11);
			return;
		} else {
			
			gspca_frame_add(gspca_dev, FIRST_PACKET, in, 0);
			sd->packet_nr = 0;
		}
	}

	
	len--;

	
	gspca_frame_add(gspca_dev, INTER_PACKET, in, len);
}

static void ov518_pkt_scan(struct gspca_dev *gspca_dev, u8 *data, int len)

{
	struct sd *sd = (struct sd *) gspca_dev;

	
	if ((!(data[0] | data[1] | data[2] | data[3] | data[5])) && data[6]) {
		ov51x_handle_button(gspca_dev, (data[6] >> 1) & 1);
		gspca_frame_add(gspca_dev, LAST_PACKET, NULL, 0);
		gspca_frame_add(gspca_dev, FIRST_PACKET, NULL, 0);
		sd->packet_nr = 0;
	}

	if (gspca_dev->last_packet_type == DISCARD_PACKET)
		return;

	
	if (len & 7) {
		len--;
		if (sd->packet_nr == data[len])
			sd->packet_nr++;
		
		else if (sd->packet_nr == 0 || data[len]) {
			gspca_err(gspca_dev, "Invalid packet nr: %d (expect: %d)\n", (int)data[len], (int)sd->packet_nr);
			gspca_dev->last_packet_type = DISCARD_PACKET;
			return;
		}
	}

	
	gspca_frame_add(gspca_dev, INTER_PACKET, data, len);
}

static void ov519_pkt_scan(struct gspca_dev *gspca_dev, u8 *data, int len)

{
	

	if (data[0] == 0xff && data[1] == 0xff && data[2] == 0xff) {
		switch (data[3]) {
		case 0x50:		
			

			data += HDRSZ;
			len -= HDRSZ;

			if (data[0] == 0xff || data[1] == 0xd8)
				gspca_frame_add(gspca_dev, FIRST_PACKET, data, len);
			else gspca_dev->last_packet_type = DISCARD_PACKET;
			return;
		case 0x51:		
			ov51x_handle_button(gspca_dev, data[11] & 1);
			if (data[9] != 0)
				gspca_dev->last_packet_type = DISCARD_PACKET;
			gspca_frame_add(gspca_dev, LAST_PACKET, NULL, 0);
			return;
		}
	}

	
	gspca_frame_add(gspca_dev, INTER_PACKET, data, len);
}

static void ovfx2_pkt_scan(struct gspca_dev *gspca_dev, u8 *data, int len)

{
	struct sd *sd = (struct sd *) gspca_dev;

	gspca_frame_add(gspca_dev, INTER_PACKET, data, len);

	
	if (len < gspca_dev->cam.bulk_size) {
		
		if (sd->first_frame) {
			sd->first_frame--;
			if (gspca_dev->image_len < sd->gspca_dev.pixfmt.width * sd->gspca_dev.pixfmt.height)

				gspca_dev->last_packet_type = DISCARD_PACKET;
		}
		gspca_frame_add(gspca_dev, LAST_PACKET, NULL, 0);
		gspca_frame_add(gspca_dev, FIRST_PACKET, NULL, 0);
	}
}

static void sd_pkt_scan(struct gspca_dev *gspca_dev, u8 *data, int len)

{
	struct sd *sd = (struct sd *) gspca_dev;

	switch (sd->bridge) {
	case BRIDGE_OV511:
	case BRIDGE_OV511PLUS:
		ov511_pkt_scan(gspca_dev, data, len);
		break;
	case BRIDGE_OV518:
	case BRIDGE_OV518PLUS:
		ov518_pkt_scan(gspca_dev, data, len);
		break;
	case BRIDGE_OV519:
		ov519_pkt_scan(gspca_dev, data, len);
		break;
	case BRIDGE_OVFX2:
		ovfx2_pkt_scan(gspca_dev, data, len);
		break;
	case BRIDGE_W9968CF:
		w9968cf_pkt_scan(gspca_dev, data, len);
		break;
	}
}



static void setbrightness(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;
	static const struct ov_i2c_regvals brit_7660[][7] = {
		{{0x0f, 0x6a}, {0x24, 0x40}, {0x25, 0x2b}, {0x26, 0x90}, {0x27, 0xe0}, {0x28, 0xe0}, {0x2c, 0xe0}}, {{0x0f, 0x6a}, {0x24, 0x50}, {0x25, 0x40}, {0x26, 0xa1}, {0x27, 0xc0}, {0x28, 0xc0}, {0x2c, 0xc0}}, {{0x0f, 0x6a}, {0x24, 0x68}, {0x25, 0x58}, {0x26, 0xc2}, {0x27, 0xa0}, {0x28, 0xa0}, {0x2c, 0xa0}}, {{0x0f, 0x6a}, {0x24, 0x70}, {0x25, 0x68}, {0x26, 0xd3}, {0x27, 0x80}, {0x28, 0x80}, {0x2c, 0x80}}, {{0x0f, 0x6a}, {0x24, 0x80}, {0x25, 0x70}, {0x26, 0xd3}, {0x27, 0x20}, {0x28, 0x20}, {0x2c, 0x20}}, {{0x0f, 0x6a}, {0x24, 0x88}, {0x25, 0x78}, {0x26, 0xd3}, {0x27, 0x40}, {0x28, 0x40}, {0x2c, 0x40}}, {{0x0f, 0x6a}, {0x24, 0x90}, {0x25, 0x80}, {0x26, 0xd4}, {0x27, 0x60}, {0x28, 0x60}, {0x2c, 0x60}}












	};

	switch (sd->sensor) {
	case SEN_OV8610:
	case SEN_OV7610:
	case SEN_OV76BE:
	case SEN_OV6620:
	case SEN_OV6630:
	case SEN_OV66308AF:
	case SEN_OV7640:
	case SEN_OV7648:
		i2c_w(sd, OV7610_REG_BRT, val);
		break;
	case SEN_OV7620:
	case SEN_OV7620AE:
		i2c_w(sd, OV7610_REG_BRT, val);
		break;
	case SEN_OV7660:
		write_i2c_regvals(sd, brit_7660[val], ARRAY_SIZE(brit_7660[0]));
		break;
	case SEN_OV7670:

		i2c_w(sd, OV7670_R55_BRIGHT, ov7670_abs_to_sm(val));
		break;
	}
}

static void setcontrast(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;
	static const struct ov_i2c_regvals contrast_7660[][31] = {
		{{0x6c, 0xf0}, {0x6d, 0xf0}, {0x6e, 0xf8}, {0x6f, 0xa0}, {0x70, 0x58}, {0x71, 0x38}, {0x72, 0x30}, {0x73, 0x30}, {0x74, 0x28}, {0x75, 0x28}, {0x76, 0x24}, {0x77, 0x24}, {0x78, 0x22}, {0x79, 0x28}, {0x7a, 0x2a}, {0x7b, 0x34}, {0x7c, 0x0f}, {0x7d, 0x1e}, {0x7e, 0x3d}, {0x7f, 0x65}, {0x80, 0x70}, {0x81, 0x77}, {0x82, 0x7d}, {0x83, 0x83}, {0x84, 0x88}, {0x85, 0x8d}, {0x86, 0x96}, {0x87, 0x9f}, {0x88, 0xb0}, {0x89, 0xc4}, {0x8a, 0xd9}}, {{0x6c, 0xf0}, {0x6d, 0xf0}, {0x6e, 0xf8}, {0x6f, 0x94}, {0x70, 0x58}, {0x71, 0x40}, {0x72, 0x30}, {0x73, 0x30}, {0x74, 0x30}, {0x75, 0x30}, {0x76, 0x2c}, {0x77, 0x24}, {0x78, 0x22}, {0x79, 0x28}, {0x7a, 0x2a}, {0x7b, 0x31}, {0x7c, 0x0f}, {0x7d, 0x1e}, {0x7e, 0x3d}, {0x7f, 0x62}, {0x80, 0x6d}, {0x81, 0x75}, {0x82, 0x7b}, {0x83, 0x81}, {0x84, 0x87}, {0x85, 0x8d}, {0x86, 0x98}, {0x87, 0xa1}, {0x88, 0xb2}, {0x89, 0xc6}, {0x8a, 0xdb}}, {{0x6c, 0xf0}, {0x6d, 0xf0}, {0x6e, 0xf0}, {0x6f, 0x84}, {0x70, 0x58}, {0x71, 0x48}, {0x72, 0x40}, {0x73, 0x40}, {0x74, 0x28}, {0x75, 0x28}, {0x76, 0x28}, {0x77, 0x24}, {0x78, 0x26}, {0x79, 0x28}, {0x7a, 0x28}, {0x7b, 0x34}, {0x7c, 0x0f}, {0x7d, 0x1e}, {0x7e, 0x3c}, {0x7f, 0x5d}, {0x80, 0x68}, {0x81, 0x71}, {0x82, 0x79}, {0x83, 0x81}, {0x84, 0x86}, {0x85, 0x8b}, {0x86, 0x95}, {0x87, 0x9e}, {0x88, 0xb1}, {0x89, 0xc5}, {0x8a, 0xd9}}, {{0x6c, 0xf0}, {0x6d, 0xf0}, {0x6e, 0xf0}, {0x6f, 0x70}, {0x70, 0x58}, {0x71, 0x58}, {0x72, 0x48}, {0x73, 0x48}, {0x74, 0x38}, {0x75, 0x40}, {0x76, 0x34}, {0x77, 0x34}, {0x78, 0x2e}, {0x79, 0x28}, {0x7a, 0x24}, {0x7b, 0x22}, {0x7c, 0x0f}, {0x7d, 0x1e}, {0x7e, 0x3c}, {0x7f, 0x58}, {0x80, 0x63}, {0x81, 0x6e}, {0x82, 0x77}, {0x83, 0x80}, {0x84, 0x87}, {0x85, 0x8f}, {0x86, 0x9c}, {0x87, 0xa9}, {0x88, 0xc0}, {0x89, 0xd4}, {0x8a, 0xe6}}, {{0x6c, 0xa0}, {0x6d, 0xf0}, {0x6e, 0x90}, {0x6f, 0x80}, {0x70, 0x70}, {0x71, 0x80}, {0x72, 0x60}, {0x73, 0x60}, {0x74, 0x58}, {0x75, 0x60}, {0x76, 0x4c}, {0x77, 0x38}, {0x78, 0x38}, {0x79, 0x2a}, {0x7a, 0x20}, {0x7b, 0x0e}, {0x7c, 0x0a}, {0x7d, 0x14}, {0x7e, 0x26}, {0x7f, 0x46}, {0x80, 0x54}, {0x81, 0x64}, {0x82, 0x70}, {0x83, 0x7c}, {0x84, 0x87}, {0x85, 0x93}, {0x86, 0xa6}, {0x87, 0xb4}, {0x88, 0xd0}, {0x89, 0xe5}, {0x8a, 0xf5}}, {{0x6c, 0x60}, {0x6d, 0x80}, {0x6e, 0x60}, {0x6f, 0x80}, {0x70, 0x80}, {0x71, 0x80}, {0x72, 0x88}, {0x73, 0x30}, {0x74, 0x70}, {0x75, 0x68}, {0x76, 0x64}, {0x77, 0x50}, {0x78, 0x3c}, {0x79, 0x22}, {0x7a, 0x10}, {0x7b, 0x08}, {0x7c, 0x06}, {0x7d, 0x0e}, {0x7e, 0x1a}, {0x7f, 0x3a}, {0x80, 0x4a}, {0x81, 0x5a}, {0x82, 0x6b}, {0x83, 0x7b}, {0x84, 0x89}, {0x85, 0x96}, {0x86, 0xaf}, {0x87, 0xc3}, {0x88, 0xe1}, {0x89, 0xf2}, {0x8a, 0xfa}}, {{0x6c, 0x20}, {0x6d, 0x40}, {0x6e, 0x20}, {0x6f, 0x60}, {0x70, 0x88}, {0x71, 0xc8}, {0x72, 0xc0}, {0x73, 0xb8}, {0x74, 0xa8}, {0x75, 0xb8}, {0x76, 0x80}, {0x77, 0x5c}, {0x78, 0x26}, {0x79, 0x10}, {0x7a, 0x08}, {0x7b, 0x04}, {0x7c, 0x02}, {0x7d, 0x06}, {0x7e, 0x0a}, {0x7f, 0x22}, {0x80, 0x33}, {0x81, 0x4c}, {0x82, 0x64}, {0x83, 0x7b}, {0x84, 0x90}, {0x85, 0xa7}, {0x86, 0xc7}, {0x87, 0xde}, {0x88, 0xf1}, {0x89, 0xf9}, {0x8a, 0xfd}}, };
























































	switch (sd->sensor) {
	case SEN_OV7610:
	case SEN_OV6620:
		i2c_w(sd, OV7610_REG_CNT, val);
		break;
	case SEN_OV6630:
	case SEN_OV66308AF:
		i2c_w_mask(sd, OV7610_REG_CNT, val >> 4, 0x0f);
		break;
	case SEN_OV8610: {
		static const u8 ctab[] = {
			0x03, 0x09, 0x0b, 0x0f, 0x53, 0x6f, 0x35, 0x7f };

		
		i2c_w(sd, 0x64, ctab[val >> 5]);
		break;
	    }
	case SEN_OV7620:
	case SEN_OV7620AE: {
		static const u8 ctab[] = {
			0x01, 0x05, 0x09, 0x11, 0x15, 0x35, 0x37, 0x57, 0x5b, 0xa5, 0xa7, 0xc7, 0xc9, 0xcf, 0xef, 0xff };


		
		i2c_w(sd, 0x64, ctab[val >> 4]);
		break;
	    }
	case SEN_OV7660:
		write_i2c_regvals(sd, contrast_7660[val], ARRAY_SIZE(contrast_7660[0]));
		break;
	case SEN_OV7670:
		
		i2c_w(sd, OV7670_R56_CONTRAS, val >> 1);
		break;
	}
}

static void setexposure(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	i2c_w(sd, 0x10, val);
}

static void setcolors(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;
	static const struct ov_i2c_regvals colors_7660[][6] = {
		{{0x4f, 0x28}, {0x50, 0x2a}, {0x51, 0x02}, {0x52, 0x0a}, {0x53, 0x19}, {0x54, 0x23}}, {{0x4f, 0x47}, {0x50, 0x4a}, {0x51, 0x03}, {0x52, 0x11}, {0x53, 0x2c}, {0x54, 0x3e}}, {{0x4f, 0x66}, {0x50, 0x6b}, {0x51, 0x05}, {0x52, 0x19}, {0x53, 0x40}, {0x54, 0x59}}, {{0x4f, 0x84}, {0x50, 0x8b}, {0x51, 0x06}, {0x52, 0x20}, {0x53, 0x53}, {0x54, 0x73}}, {{0x4f, 0xa3}, {0x50, 0xab}, {0x51, 0x08}, {0x52, 0x28}, {0x53, 0x66}, {0x54, 0x8e}}, };










	switch (sd->sensor) {
	case SEN_OV8610:
	case SEN_OV7610:
	case SEN_OV76BE:
	case SEN_OV6620:
	case SEN_OV6630:
	case SEN_OV66308AF:
		i2c_w(sd, OV7610_REG_SAT, val);
		break;
	case SEN_OV7620:
	case SEN_OV7620AE:
		

		i2c_w(sd, OV7610_REG_SAT, val);
		break;
	case SEN_OV7640:
	case SEN_OV7648:
		i2c_w(sd, OV7610_REG_SAT, val & 0xf0);
		break;
	case SEN_OV7660:
		write_i2c_regvals(sd, colors_7660[val], ARRAY_SIZE(colors_7660[0]));
		break;
	case SEN_OV7670:
		
		
		break;
	}
}

static void setautobright(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	i2c_w_mask(sd, 0x2d, val ? 0x10 : 0x00, 0x10);
}

static void setfreq_i(struct sd *sd, s32 val)
{
	if (sd->sensor == SEN_OV7660 || sd->sensor == SEN_OV7670) {
		switch (val) {
		case 0: 
			i2c_w_mask(sd, OV7670_R13_COM8, 0, OV7670_COM8_BFILT);
			break;
		case 1: 
			i2c_w_mask(sd, OV7670_R13_COM8, OV7670_COM8_BFILT, OV7670_COM8_BFILT);
			i2c_w_mask(sd, OV7670_R3B_COM11, 0x08, 0x18);
			break;
		case 2: 
			i2c_w_mask(sd, OV7670_R13_COM8, OV7670_COM8_BFILT, OV7670_COM8_BFILT);
			i2c_w_mask(sd, OV7670_R3B_COM11, 0x00, 0x18);
			break;
		case 3: 
			i2c_w_mask(sd, OV7670_R13_COM8, OV7670_COM8_BFILT, OV7670_COM8_BFILT);
			i2c_w_mask(sd, OV7670_R3B_COM11, OV7670_COM11_HZAUTO, 0x18);
			break;
		}
	} else {
		switch (val) {
		case 0: 
			i2c_w_mask(sd, 0x2d, 0x00, 0x04);
			i2c_w_mask(sd, 0x2a, 0x00, 0x80);
			break;
		case 1: 
			i2c_w_mask(sd, 0x2d, 0x04, 0x04);
			i2c_w_mask(sd, 0x2a, 0x80, 0x80);
			
			if (sd->sensor == SEN_OV6620 || sd->sensor == SEN_OV6630 || sd->sensor == SEN_OV66308AF)

				i2c_w(sd, 0x2b, 0x5e);
			else i2c_w(sd, 0x2b, 0xac);
			break;
		case 2: 
			i2c_w_mask(sd, 0x2d, 0x04, 0x04);
			if (sd->sensor == SEN_OV6620 || sd->sensor == SEN_OV6630 || sd->sensor == SEN_OV66308AF) {

				
				i2c_w_mask(sd, 0x2a, 0x80, 0x80);
				i2c_w(sd, 0x2b, 0xa8);
			} else {
				
				i2c_w_mask(sd, 0x2a, 0x00, 0x80);
			}
			break;
		}
	}
}

static void setfreq(struct gspca_dev *gspca_dev, s32 val)
{
	struct sd *sd = (struct sd *) gspca_dev;

	setfreq_i(sd, val);

	
	if (sd->bridge == BRIDGE_W9968CF)
		w9968cf_set_crop_window(sd);
}

static int sd_get_jcomp(struct gspca_dev *gspca_dev, struct v4l2_jpegcompression *jcomp)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (sd->bridge != BRIDGE_W9968CF)
		return -ENOTTY;

	memset(jcomp, 0, sizeof *jcomp);
	jcomp->quality = v4l2_ctrl_g_ctrl(sd->jpegqual);
	jcomp->jpeg_markers = V4L2_JPEG_MARKER_DHT | V4L2_JPEG_MARKER_DQT | V4L2_JPEG_MARKER_DRI;
	return 0;
}

static int sd_set_jcomp(struct gspca_dev *gspca_dev, const struct v4l2_jpegcompression *jcomp)
{
	struct sd *sd = (struct sd *) gspca_dev;

	if (sd->bridge != BRIDGE_W9968CF)
		return -ENOTTY;

	v4l2_ctrl_s_ctrl(sd->jpegqual, jcomp->quality);
	return 0;
}

static int sd_g_volatile_ctrl(struct v4l2_ctrl *ctrl)
{
	struct gspca_dev *gspca_dev = container_of(ctrl->handler, struct gspca_dev, ctrl_handler);
	struct sd *sd = (struct sd *)gspca_dev;

	gspca_dev->usb_err = 0;

	switch (ctrl->id) {
	case V4L2_CID_AUTOGAIN:
		gspca_dev->exposure->val = i2c_r(sd, 0x10);
		break;
	}
	return 0;
}

static int sd_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct gspca_dev *gspca_dev = container_of(ctrl->handler, struct gspca_dev, ctrl_handler);
	struct sd *sd = (struct sd *)gspca_dev;

	gspca_dev->usb_err = 0;

	if (!gspca_dev->streaming)
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_BRIGHTNESS:
		setbrightness(gspca_dev, ctrl->val);
		break;
	case V4L2_CID_CONTRAST:
		setcontrast(gspca_dev, ctrl->val);
		break;
	case V4L2_CID_POWER_LINE_FREQUENCY:
		setfreq(gspca_dev, ctrl->val);
		break;
	case V4L2_CID_AUTOBRIGHTNESS:
		if (ctrl->is_new)
			setautobright(gspca_dev, ctrl->val);
		if (!ctrl->val && sd->brightness->is_new)
			setbrightness(gspca_dev, sd->brightness->val);
		break;
	case V4L2_CID_SATURATION:
		setcolors(gspca_dev, ctrl->val);
		break;
	case V4L2_CID_HFLIP:
		sethvflip(gspca_dev, ctrl->val, sd->vflip->val);
		break;
	case V4L2_CID_AUTOGAIN:
		if (ctrl->is_new)
			setautogain(gspca_dev, ctrl->val);
		if (!ctrl->val && gspca_dev->exposure->is_new)
			setexposure(gspca_dev, gspca_dev->exposure->val);
		break;
	case V4L2_CID_JPEG_COMPRESSION_QUALITY:
		return -EBUSY; 
	}
	return gspca_dev->usb_err;
}

static const struct v4l2_ctrl_ops sd_ctrl_ops = {
	.g_volatile_ctrl = sd_g_volatile_ctrl, .s_ctrl = sd_s_ctrl, };


static int sd_init_controls(struct gspca_dev *gspca_dev)
{
	struct sd *sd = (struct sd *)gspca_dev;
	struct v4l2_ctrl_handler *hdl = &gspca_dev->ctrl_handler;

	gspca_dev->vdev.ctrl_handler = hdl;
	v4l2_ctrl_handler_init(hdl, 10);
	if (valid_controls[sd->sensor].has_brightness)
		sd->brightness = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_BRIGHTNESS, 0, sd->sensor == SEN_OV7660 ? 6 : 255, 1, sd->sensor == SEN_OV7660 ? 3 : 127);


	if (valid_controls[sd->sensor].has_contrast) {
		if (sd->sensor == SEN_OV7660)
			v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_CONTRAST, 0, 6, 1, 3);
		else v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_CONTRAST, 0, 255, 1, (sd->sensor == SEN_OV6630 || sd->sensor == SEN_OV66308AF) ? 200 : 127);



	}
	if (valid_controls[sd->sensor].has_sat)
		v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_SATURATION, 0, sd->sensor == SEN_OV7660 ? 4 : 255, 1, sd->sensor == SEN_OV7660 ? 2 : 127);


	if (valid_controls[sd->sensor].has_exposure)
		gspca_dev->exposure = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_EXPOSURE, 0, 255, 1, 127);
	if (valid_controls[sd->sensor].has_hvflip) {
		sd->hflip = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_HFLIP, 0, 1, 1, 0);
		sd->vflip = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_VFLIP, 0, 1, 1, 0);
	}
	if (valid_controls[sd->sensor].has_autobright)
		sd->autobright = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_AUTOBRIGHTNESS, 0, 1, 1, 1);
	if (valid_controls[sd->sensor].has_autogain)
		gspca_dev->autogain = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_AUTOGAIN, 0, 1, 1, 1);
	if (valid_controls[sd->sensor].has_freq) {
		if (sd->sensor == SEN_OV7670)
			sd->freq = v4l2_ctrl_new_std_menu(hdl, &sd_ctrl_ops, V4L2_CID_POWER_LINE_FREQUENCY, V4L2_CID_POWER_LINE_FREQUENCY_AUTO, 0, V4L2_CID_POWER_LINE_FREQUENCY_AUTO);


		else sd->freq = v4l2_ctrl_new_std_menu(hdl, &sd_ctrl_ops, V4L2_CID_POWER_LINE_FREQUENCY, V4L2_CID_POWER_LINE_FREQUENCY_60HZ, 0, 0);


	}
	if (sd->bridge == BRIDGE_W9968CF)
		sd->jpegqual = v4l2_ctrl_new_std(hdl, &sd_ctrl_ops, V4L2_CID_JPEG_COMPRESSION_QUALITY, QUALITY_MIN, QUALITY_MAX, 1, QUALITY_DEF);


	if (hdl->error) {
		gspca_err(gspca_dev, "Could not initialize controls\n");
		return hdl->error;
	}
	if (gspca_dev->autogain)
		v4l2_ctrl_auto_cluster(3, &gspca_dev->autogain, 0, true);
	if (sd->autobright)
		v4l2_ctrl_auto_cluster(2, &sd->autobright, 0, false);
	if (sd->hflip)
		v4l2_ctrl_cluster(2, &sd->hflip);
	return 0;
}


static const struct sd_desc sd_desc = {
	.name = MODULE_NAME, .config = sd_config, .init = sd_init, .init_controls = sd_init_controls, .isoc_init = sd_isoc_init, .start = sd_start, .stopN = sd_stopN, .stop0 = sd_stop0, .pkt_scan = sd_pkt_scan, .dq_callback = sd_reset_snapshot, .get_jcomp = sd_get_jcomp, .set_jcomp = sd_set_jcomp,  .other_input = 1,  };
















static const struct usb_device_id device_table[] = {
	{USB_DEVICE(0x041e, 0x4003), .driver_info = BRIDGE_W9968CF }, {USB_DEVICE(0x041e, 0x4052), .driver_info = BRIDGE_OV519 | BRIDGE_INVERT_LED }, {USB_DEVICE(0x041e, 0x405f), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x041e, 0x4060), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x041e, 0x4061), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x041e, 0x4064), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x041e, 0x4067), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x041e, 0x4068), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x045e, 0x028c), .driver_info = BRIDGE_OV519 | BRIDGE_INVERT_LED }, {USB_DEVICE(0x054c, 0x0154), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x054c, 0x0155), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x05a9, 0x0511), .driver_info = BRIDGE_OV511 }, {USB_DEVICE(0x05a9, 0x0518), .driver_info = BRIDGE_OV518 }, {USB_DEVICE(0x05a9, 0x0519), .driver_info = BRIDGE_OV519 | BRIDGE_INVERT_LED }, {USB_DEVICE(0x05a9, 0x0530), .driver_info = BRIDGE_OV519 | BRIDGE_INVERT_LED }, {USB_DEVICE(0x05a9, 0x2800), .driver_info = BRIDGE_OVFX2 }, {USB_DEVICE(0x05a9, 0x4519), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x05a9, 0x8519), .driver_info = BRIDGE_OV519 }, {USB_DEVICE(0x05a9, 0xa511), .driver_info = BRIDGE_OV511PLUS }, {USB_DEVICE(0x05a9, 0xa518), .driver_info = BRIDGE_OV518PLUS }, {USB_DEVICE(0x0813, 0x0002), .driver_info = BRIDGE_OV511PLUS }, {USB_DEVICE(0x0b62, 0x0059), .driver_info = BRIDGE_OVFX2 }, {USB_DEVICE(0x0e96, 0xc001), .driver_info = BRIDGE_OVFX2 }, {USB_DEVICE(0x1046, 0x9967), .driver_info = BRIDGE_W9968CF }, {USB_DEVICE(0x8020, 0xef04), .driver_info = BRIDGE_OVFX2 }, {}




























};

MODULE_DEVICE_TABLE(usb, device_table);


static int sd_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	return gspca_dev_probe(intf, id, &sd_desc, sizeof(struct sd), THIS_MODULE);
}

static struct usb_driver sd_driver = {
	.name = MODULE_NAME, .id_table = device_table, .probe = sd_probe, .disconnect = gspca_disconnect,  .suspend = gspca_suspend, .resume = gspca_resume, .reset_resume = gspca_resume,  };









module_usb_driver(sd_driver);

module_param(frame_rate, int, 0644);
MODULE_PARM_DESC(frame_rate, "Frame rate (5, 10, 15, 20 or 30 fps)");
