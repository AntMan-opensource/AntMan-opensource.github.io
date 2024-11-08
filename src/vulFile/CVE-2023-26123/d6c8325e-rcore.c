





    #include "config.h"             











    #define GESTURES_IMPLEMENTATION
    #include "rgestures.h"           



    #define CAMERA_IMPLEMENTATION
    #include "rcamera.h"             



    #define MSF_GIF_MALLOC(contextPointer, newSize) RL_MALLOC(newSize)
    #define MSF_GIF_REALLOC(contextPointer, oldMemory, oldSize, newSize) RL_REALLOC(oldMemory, newSize)
    #define MSF_GIF_FREE(contextPointer, oldMemory, oldSize) RL_FREE(oldMemory)

    #define MSF_GIF_IMPL
    #include "external/msf_gif.h"   



    #define SINFL_IMPLEMENTATION
    #define SINFL_NO_SIMD
    #include "external/sinfl.h"     

    #define SDEFL_IMPLEMENTATION
    #include "external/sdefl.h"     



    #undef _POSIX_C_SOURCE
    #define _POSIX_C_SOURCE 199309L 


    #define _GNU_SOURCE




    #if defined(_WIN32)
        #ifndef MAX_PATH
            #define MAX_PATH 1025
        #endif
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void *hModule, void *lpFilename, unsigned long nSize);
    __declspec(dllimport) unsigned long __stdcall GetModuleFileNameW(void *hModule, void *lpFilename, unsigned long nSize);
    __declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned int cp, unsigned long flags, void *widestr, int cchwide, void *str, int cbmb, void *defchar, int *used_default);
    #elif defined(__linux__)
        #include <unistd.h>
    #elif defined(__APPLE__)
        #include <sys/syslimits.h>
        #include <mach-o/dyld.h>
    #endif 












    #define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)



    #define DIRENT_MALLOC RL_MALLOC
    #define DIRENT_FREE RL_FREE

    #include "external/dirent.h"    

    #include <dirent.h>             



    #include <direct.h>             
    #define GETCWD _getcwd          
    #define CHDIR _chdir
    #include <io.h>                 

    #include <unistd.h>             
    #define GETCWD getcwd
    #define CHDIR chdir



    #define GLFW_INCLUDE_NONE       
                                    
    #include "GLFW/glfw3.h"         
                                    

    
    #if defined(_WIN32)
        typedef void *PVOID;
        typedef PVOID HANDLE;
        typedef HANDLE HWND;
        #define GLFW_EXPOSE_NATIVE_WIN32
        #define GLFW_NATIVE_INCLUDE_NONE 
        #include "GLFW/glfw3native.h"

        #if defined(SUPPORT_WINMM_HIGHRES_TIMER) && !defined(SUPPORT_BUSY_WAIT_LOOP)
            
            unsigned int __stdcall timeBeginPeriod(unsigned int uPeriod);
            unsigned int __stdcall timeEndPeriod(unsigned int uPeriod);
        #endif
    #endif
    #if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        #include <sys/time.h>               

        
        
        
        #include "GLFW/glfw3native.h"       
    #endif
    #if defined(__APPLE__)
        #include <unistd.h>                 

        
        void *glfwGetCocoaWindow(GLFWwindow* handle);
        #include "GLFW/glfw3native.h"       
    #endif

    
    
    #if !defined(GLFW_MOUSE_PASSTHROUGH)
        #define GLFW_MOUSE_PASSTHROUGH      0x0002000D
    #endif



    
    #include <android/window.h>             
    #include <android_native_app_glue.h>    
    #include <jni.h>                        

    #include <EGL/egl.h>                    
    



    #include <fcntl.h>                  
    #include <unistd.h>                 
    #include <termios.h>                
    #include <pthread.h>                
    #include <dirent.h>                 

    #include <sys/ioctl.h>              
    #include <linux/kd.h>               
    #include <linux/input.h>            
    #include <linux/joystick.h>         


    #include "bcm_host.h"               


    #include <gbm.h>                    
    #include <xf86drm.h>                
    #include <xf86drmMode.h>            


    #include "EGL/egl.h"                
    #include "EGL/eglext.h"             
    



    #define GLFW_INCLUDE_ES2            
    #include "GLFW/glfw3.h"             
    #include <sys/time.h>               

    #include <emscripten/emscripten.h>  
    #include <emscripten/html5.h>       






    #define USE_LAST_TOUCH_DEVICE       

    #define DEFAULT_GAMEPAD_DEV    "/dev/input/js"  
    #define DEFAULT_EVDEV_PATH       "/dev/input/"  



    #define MAX_FILEPATH_CAPACITY       8192        


    #define MAX_FILEPATH_LENGTH         4096        



    #define MAX_KEYBOARD_KEYS            512        


    #define MAX_MOUSE_BUTTONS              8        


    #define MAX_GAMEPADS                   4        


    #define MAX_GAMEPAD_AXIS               8        


    #define MAX_GAMEPAD_BUTTONS           32        


    #define MAX_TOUCH_POINTS               8        


    #define MAX_KEY_PRESSED_QUEUE         16        


    #define MAX_CHAR_PRESSED_QUEUE        16        



    #define MAX_DECOMPRESSION_SIZE        64        












typedef struct {
    pthread_t threadId;             
    int fd;                         
    int eventNum;                   
    Rectangle absRange;             
    int touchSlot;                  
    bool isMouse;                   
    bool isTouch;                   
    bool isMultitouch;              
    bool isKeyboard;                
    bool isGamepad;                 
} InputEventWorker;


typedef struct { int x; int y; } Point;
typedef struct { unsigned int width; unsigned int height; } Size;


typedef struct CoreData {
    struct {

        GLFWwindow *handle;                 


        EGL_DISPMANX_WINDOW_T handle;       



        int fd;                             
        drmModeConnector *connector;        
        drmModeCrtc *crtc;                  
        int modeIndex;                      
        struct gbm_device *gbmDevice;       
        struct gbm_surface *gbmSurface;     
        struct gbm_bo *prevBO;              
        uint32_t prevFB;                    

        EGLDisplay device;                  
        EGLSurface surface;                 
        EGLContext context;                 
        EGLConfig config;                   

        const char *title;                  
        unsigned int flags;                 
        bool ready;                         
        bool fullscreen;                    
        bool shouldClose;                   
        bool resizedLastFrame;              
        bool eventWaiting;                  

        Point position;                     
        Size display;                       
        Size screen;                        
        Size currentFbo;                    
        Size render;                        
        Point renderOffset;                 
        Matrix screenScale;                 

        char **dropFilepaths;         
        unsigned int dropFileCount;         

    } Window;

    struct {
        bool appEnabled;                    
        struct android_app *app;            
        struct android_poll_source *source; 
        bool contextRebindRequired;         
    } Android;

    struct {
        const char *basePath;               
    } Storage;
    struct {

        InputEventWorker eventWorker[10];   

        struct {
            int exitKey;                    
            char currentKeyState[MAX_KEYBOARD_KEYS];        
            char previousKeyState[MAX_KEYBOARD_KEYS];       

            int keyPressedQueue[MAX_KEY_PRESSED_QUEUE];     
            int keyPressedQueueCount;       

            int charPressedQueue[MAX_CHAR_PRESSED_QUEUE];   
            int charPressedQueueCount;      


            int defaultMode;                

            bool evtMode;                   

            int defaultFileFlags;           
            struct termios defaultSettings; 
            int fd;                         

        } Keyboard;
        struct {
            Vector2 offset;                 
            Vector2 scale;                  
            Vector2 currentPosition;        
            Vector2 previousPosition;       

            int cursor;                     
            bool cursorHidden;              
            bool cursorOnScreen;            

            char currentButtonState[MAX_MOUSE_BUTTONS];     
            char previousButtonState[MAX_MOUSE_BUTTONS];    
            Vector2 currentWheelMove;       
            Vector2 previousWheelMove;      

            
            char currentButtonStateEvdev[MAX_MOUSE_BUTTONS]; 

        } Mouse;
        struct {
            int pointCount;                             
            int pointId[MAX_TOUCH_POINTS];              
            Vector2 position[MAX_TOUCH_POINTS];         
            char currentTouchState[MAX_TOUCH_POINTS];   
            char previousTouchState[MAX_TOUCH_POINTS];  
        } Touch;
        struct {
            int lastButtonPressed;          
            int axisCount;                  
            bool ready[MAX_GAMEPADS];       
            char name[MAX_GAMEPADS][64];    
            char currentButtonState[MAX_GAMEPADS][MAX_GAMEPAD_BUTTONS];     
            char previousButtonState[MAX_GAMEPADS][MAX_GAMEPAD_BUTTONS];    
            float axisState[MAX_GAMEPADS][MAX_GAMEPAD_AXIS];                

            pthread_t threadId;             
            int streamId[MAX_GAMEPADS];     

        } Gamepad;
    } Input;
    struct {
        double current;                     
        double previous;                    
        double update;                      
        double draw;                        
        double frame;                       
        double target;                      

        unsigned long long base;            

        unsigned int frameCounter;          
    } Time;
} CoreData;




RLAPI const char *raylib_version = RAYLIB_VERSION;  

static CoreData CORE = { 0 };               


static int screenshotCounter = 0;           



static int gifFrameCounter = 0;             
static bool gifRecording = false;           
static MsfGifState gifState = { 0 };        





typedef enum AutomationEventType {
    EVENT_NONE = 0,  INPUT_KEY_UP, INPUT_KEY_DOWN, INPUT_KEY_PRESSED, INPUT_KEY_RELEASED, INPUT_MOUSE_BUTTON_UP, INPUT_MOUSE_BUTTON_DOWN, INPUT_MOUSE_POSITION, INPUT_MOUSE_WHEEL_MOTION, INPUT_GAMEPAD_CONNECT, INPUT_GAMEPAD_DISCONNECT, INPUT_GAMEPAD_BUTTON_UP, INPUT_GAMEPAD_BUTTON_DOWN, INPUT_GAMEPAD_AXIS_MOTION, INPUT_TOUCH_UP, INPUT_TOUCH_DOWN, INPUT_TOUCH_POSITION, INPUT_GESTURE,  WINDOW_CLOSE, WINDOW_MAXIMIZE, WINDOW_MINIMIZE, WINDOW_RESIZE,  ACTION_TAKE_SCREENSHOT, ACTION_SETTARGETFPS } AutomationEventType;





























typedef enum {
    EVENT_INPUT_KEYBOARD    = 0, EVENT_INPUT_MOUSE       = 1, EVENT_INPUT_GAMEPAD     = 2, EVENT_INPUT_TOUCH       = 4, EVENT_INPUT_GESTURE     = 8, EVENT_WINDOW            = 16, EVENT_CUSTOM            = 32 } EventType;







static const char *autoEventTypeName[] = {
    "EVENT_NONE", "INPUT_KEY_UP", "INPUT_KEY_DOWN", "INPUT_KEY_PRESSED", "INPUT_KEY_RELEASED", "INPUT_MOUSE_BUTTON_UP", "INPUT_MOUSE_BUTTON_DOWN", "INPUT_MOUSE_POSITION", "INPUT_MOUSE_WHEEL_MOTION", "INPUT_GAMEPAD_CONNECT", "INPUT_GAMEPAD_DISCONNECT", "INPUT_GAMEPAD_BUTTON_UP", "INPUT_GAMEPAD_BUTTON_DOWN", "INPUT_GAMEPAD_AXIS_MOTION", "INPUT_TOUCH_UP", "INPUT_TOUCH_DOWN", "INPUT_TOUCH_POSITION", "INPUT_GESTURE", "WINDOW_CLOSE", "WINDOW_MAXIMIZE", "WINDOW_MINIMIZE", "WINDOW_RESIZE", "ACTION_TAKE_SCREENSHOT", "ACTION_SETTARGETFPS" };

























typedef struct AutomationEvent {
    unsigned int frame;                 
    unsigned int type;                  
    int params[3];                      
} AutomationEvent;

static AutomationEvent *events = NULL;        
static unsigned int eventCount = 0;     
static bool eventsPlaying = false;      
static bool eventsRecording = false;    









extern void LoadFontDefault(void);          
extern void UnloadFontDefault(void);        





static void InitTimer(void);                            
static bool InitGraphicsDevice(int width, int height);  
static void SetupFramebuffer(int width, int height);    
static void SetupViewport(int width, int height);       

static void ScanDirectoryFiles(const char *basePath, FilePathList *list, const char *filter);   
static void ScanDirectoryFilesRecursively(const char *basePath, FilePathList *list, const char *filter);  


static void ErrorCallback(int error, const char *description);                             

static void WindowSizeCallback(GLFWwindow *window, int width, int height);                 

static void WindowMaximizeCallback(GLFWwindow* window, int maximized);                     

static void WindowIconifyCallback(GLFWwindow *window, int iconified);                      
static void WindowFocusCallback(GLFWwindow *window, int focused);                          
static void WindowDropCallback(GLFWwindow *window, int count, const char **paths);         

static void KeyCallback(GLFWwindow *window, int key, int scancode, int action, int mods);  
static void CharCallback(GLFWwindow *window, unsigned int key);                            
static void MouseButtonCallback(GLFWwindow *window, int button, int action, int mods);     
static void MouseCursorPosCallback(GLFWwindow *window, double x, double y);                
static void MouseScrollCallback(GLFWwindow *window, double xoffset, double yoffset);       
static void CursorEnterCallback(GLFWwindow *window, int enter);                            



static void AndroidCommandCallback(struct android_app *app, int32_t cmd);                  
static int32_t AndroidInputCallback(struct android_app *app, AInputEvent *event);          



static EM_BOOL EmscriptenFullscreenChangeCallback(int eventType, const EmscriptenFullscreenChangeEvent *event, void *userData);
static EM_BOOL EmscriptenWindowResizedCallback(int eventType, const EmscriptenUiEvent *event, void *userData);
static EM_BOOL EmscriptenResizeCallback(int eventType, const EmscriptenUiEvent *event, void *userData);

static EM_BOOL EmscriptenMouseCallback(int eventType, const EmscriptenMouseEvent *mouseEvent, void *userData);
static EM_BOOL EmscriptenTouchCallback(int eventType, const EmscriptenTouchEvent *touchEvent, void *userData);
static EM_BOOL EmscriptenGamepadCallback(int eventType, const EmscriptenGamepadEvent *gamepadEvent, void *userData);



static void InitKeyboard(void);                         
static void RestoreKeyboard(void);                      

static void ProcessKeyboard(void);                      


static void InitEvdevInput(void);                       
static void ConfigureEvdevDevice(char *device);         
static void PollKeyboardEvents(void);                   
static void *EventThread(void *arg);                    

static void InitGamepad(void);                          
static void *GamepadThread(void *arg);                  


static int FindMatchingConnectorMode(const drmModeConnector *connector, const drmModeModeInfo *mode);                               
static int FindExactConnectorMode(const drmModeConnector *connector, uint width, uint height, uint fps, bool allowInterlaced);      
static int FindNearestConnectorMode(const drmModeConnector *connector, uint width, uint height, uint fps, bool allowInterlaced);    





static void LoadAutomationEvents(const char *fileName);     
static void ExportAutomationEvents(const char *fileName);   
static void RecordAutomationEvent(unsigned int frame);      
static void PlayAutomationEvent(unsigned int frame);        




void __stdcall Sleep(unsigned long msTimeout);              



const char *TextFormat(const char *text, ...);       








extern int main(int argc, char *argv[]);

void android_main(struct android_app *app)
{
    char arg0[] = "raylib";     
    CORE.Android.app = app;

    
    (void)main(1, (char *[]) { arg0, NULL });
}


struct android_app *GetAndroidApp(void)
{
    return CORE.Android.app;
}




void InitWindow(int width, int height, const char *title)
{
    TRACELOG(LOG_INFO, "Initializing raylib %s", RAYLIB_VERSION);

    TRACELOG(LOG_INFO, "Supported raylib modules:");
    TRACELOG(LOG_INFO, "    > rcore:..... loaded (mandatory)");
    TRACELOG(LOG_INFO, "    > rlgl:...... loaded (mandatory)");

    TRACELOG(LOG_INFO, "    > rshapes:... loaded (optional)");

    TRACELOG(LOG_INFO, "    > rshapes:... not loaded (optional)");


    TRACELOG(LOG_INFO, "    > rtextures:. loaded (optional)");

    TRACELOG(LOG_INFO, "    > rtextures:. not loaded (optional)");


    TRACELOG(LOG_INFO, "    > rtext:..... loaded (optional)");

    TRACELOG(LOG_INFO, "    > rtext:..... not loaded (optional)");


    TRACELOG(LOG_INFO, "    > rmodels:... loaded (optional)");

    TRACELOG(LOG_INFO, "    > rmodels:... not loaded (optional)");


    TRACELOG(LOG_INFO, "    > raudio:.... loaded (optional)");

    TRACELOG(LOG_INFO, "    > raudio:.... not loaded (optional)");


    if ((title != NULL) && (title[0] != 0)) CORE.Window.title = title;

    
    memset(&CORE.Input, 0, sizeof(CORE.Input));
    CORE.Input.Keyboard.exitKey = KEY_ESCAPE;
    CORE.Input.Mouse.scale = (Vector2){ 1.0f, 1.0f };
    CORE.Input.Mouse.cursor = MOUSE_CURSOR_ARROW;
    CORE.Input.Gamepad.lastButtonPressed = 0;       

    CORE.Window.eventWaiting = true;



    CORE.Window.screen.width = width;
    CORE.Window.screen.height = height;
    CORE.Window.currentFbo.width = width;
    CORE.Window.currentFbo.height = height;

    
    ANativeActivity_setWindowFlags(CORE.Android.app->activity, AWINDOW_FLAG_FULLSCREEN, 0);  

    int orientation = AConfiguration_getOrientation(CORE.Android.app->config);

    if (orientation == ACONFIGURATION_ORIENTATION_PORT) TRACELOG(LOG_INFO, "ANDROID: Window orientation set as portrait");
    else if (orientation == ACONFIGURATION_ORIENTATION_LAND) TRACELOG(LOG_INFO, "ANDROID: Window orientation set as landscape");

    
    if (width <= height)
    {
        AConfiguration_setOrientation(CORE.Android.app->config, ACONFIGURATION_ORIENTATION_PORT);
        TRACELOG(LOG_WARNING, "ANDROID: Window orientation changed to portrait");
    }
    else {
        AConfiguration_setOrientation(CORE.Android.app->config, ACONFIGURATION_ORIENTATION_LAND);
        TRACELOG(LOG_WARNING, "ANDROID: Window orientation changed to landscape");
    }

    
    
    
    

    
    
    CORE.Android.app->onAppCmd = AndroidCommandCallback;

    
    CORE.Android.app->onInputEvent = AndroidInputCallback;

    
    InitAssetManager(CORE.Android.app->activity->assetManager, CORE.Android.app->activity->internalDataPath);

    
    CORE.Storage.basePath = CORE.Android.app->activity->internalDataPath;

    TRACELOG(LOG_INFO, "ANDROID: App initialized successfully");

    
    int pollResult = 0;
    int pollEvents = 0;

    
    while (!CORE.Window.ready)
    {
        
        while ((pollResult = ALooper_pollAll(0, NULL, &pollEvents, (void**)&CORE.Android.source)) >= 0)
        {
            
            if (CORE.Android.source != NULL) CORE.Android.source->process(CORE.Android.app, CORE.Android.source);

            
            
        }
    }


    
    
    CORE.Window.ready = InitGraphicsDevice(width, height);

    
    if (!CORE.Window.ready)
    {
        TRACELOG(LOG_FATAL, "Failed to initialize Graphic Device");
        return;
    }
    else SetWindowPosition(GetMonitorWidth(GetCurrentMonitor())/2 - CORE.Window.screen.width/2, GetMonitorHeight(GetCurrentMonitor())/2 - CORE.Window.screen.height/2);

    
    InitTimer();

    
    srand((unsigned int)time(NULL));

    
    CORE.Storage.basePath = GetWorkingDirectory();


    
    
    LoadFontDefault();
    #if defined(SUPPORT_MODULE_RSHAPES)
    Rectangle rec = GetFontDefault().recs[95];
    
    SetShapesTexture(GetFontDefault().texture, (Rectangle){ rec.x + 1, rec.y + 1, rec.width - 2, rec.height - 2 }); 
    #endif

    #if defined(SUPPORT_MODULE_RSHAPES)
    
    
    Texture2D texture = { rlGetTextureIdDefault(), 1, 1, 1, PIXELFORMAT_UNCOMPRESSED_R8G8B8A8 };
    SetShapesTexture(texture, (Rectangle){ 0.0f, 0.0f, 1.0f, 1.0f });    
    #endif


    if ((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) > 0)
    {
        
        
        rlTextureParameters(GetFontDefault().texture.id, RL_TEXTURE_MIN_FILTER, RL_TEXTURE_FILTER_LINEAR);
        rlTextureParameters(GetFontDefault().texture.id, RL_TEXTURE_MAG_FILTER, RL_TEXTURE_FILTER_LINEAR);
    }



    
    InitEvdevInput();   
    InitGamepad();      
    InitKeyboard();     



    
    emscripten_set_fullscreenchange_callback("#canvas", NULL, 1, EmscriptenFullscreenChangeCallback);

    
    
    
    
    
    
    

    
    
    

    
    emscripten_set_click_callback("#canvas", NULL, 1, EmscriptenMouseCallback);

    
    emscripten_set_touchstart_callback("#canvas", NULL, 1, EmscriptenTouchCallback);
    emscripten_set_touchend_callback("#canvas", NULL, 1, EmscriptenTouchCallback);
    emscripten_set_touchmove_callback("#canvas", NULL, 1, EmscriptenTouchCallback);
    emscripten_set_touchcancel_callback("#canvas", NULL, 1, EmscriptenTouchCallback);

    
    emscripten_set_gamepadconnected_callback(NULL, 1, EmscriptenGamepadCallback);
    emscripten_set_gamepaddisconnected_callback(NULL, 1, EmscriptenGamepadCallback);



    events = (AutomationEvent *)malloc(MAX_CODE_AUTOMATION_EVENTS*sizeof(AutomationEvent));
    CORE.Time.frameCounter = 0;



}


void CloseWindow(void)
{

    if (gifRecording)
    {
        MsfGifResult result = msf_gif_end(&gifState);
        msf_gif_free(result);
        gifRecording = false;
    }



    UnloadFontDefault();        


    rlglClose();                


    glfwDestroyWindow(CORE.Window.handle);
    glfwTerminate();



    timeEndPeriod(1);           



    
    if (CORE.Window.device != EGL_NO_DISPLAY)
    {
        eglMakeCurrent(CORE.Window.device, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);

        if (CORE.Window.surface != EGL_NO_SURFACE)
        {
            eglDestroySurface(CORE.Window.device, CORE.Window.surface);
            CORE.Window.surface = EGL_NO_SURFACE;
        }

        if (CORE.Window.context != EGL_NO_CONTEXT)
        {
            eglDestroyContext(CORE.Window.device, CORE.Window.context);
            CORE.Window.context = EGL_NO_CONTEXT;
        }

        eglTerminate(CORE.Window.device);
        CORE.Window.device = EGL_NO_DISPLAY;
    }



    if (CORE.Window.prevFB)
    {
        drmModeRmFB(CORE.Window.fd, CORE.Window.prevFB);
        CORE.Window.prevFB = 0;
    }

    if (CORE.Window.prevBO)
    {
        gbm_surface_release_buffer(CORE.Window.gbmSurface, CORE.Window.prevBO);
        CORE.Window.prevBO = NULL;
    }

    if (CORE.Window.gbmSurface)
    {
        gbm_surface_destroy(CORE.Window.gbmSurface);
        CORE.Window.gbmSurface = NULL;
    }

    if (CORE.Window.gbmDevice)
    {
        gbm_device_destroy(CORE.Window.gbmDevice);
        CORE.Window.gbmDevice = NULL;
    }

    if (CORE.Window.crtc)
    {
        if (CORE.Window.connector)
        {
            drmModeSetCrtc(CORE.Window.fd, CORE.Window.crtc->crtc_id, CORE.Window.crtc->buffer_id, CORE.Window.crtc->x, CORE.Window.crtc->y, &CORE.Window.connector->connector_id, 1, &CORE.Window.crtc->mode);
            drmModeFreeConnector(CORE.Window.connector);
            CORE.Window.connector = NULL;
        }

        drmModeFreeCrtc(CORE.Window.crtc);
        CORE.Window.crtc = NULL;
    }

    if (CORE.Window.fd != -1)
    {
        close(CORE.Window.fd);
        CORE.Window.fd = -1;
    }

    
    if (CORE.Window.device != EGL_NO_DISPLAY)
    {
        if (CORE.Window.surface != EGL_NO_SURFACE)
        {
            eglDestroySurface(CORE.Window.device, CORE.Window.surface);
            CORE.Window.surface = EGL_NO_SURFACE;
        }

        if (CORE.Window.context != EGL_NO_CONTEXT)
        {
            eglDestroyContext(CORE.Window.device, CORE.Window.context);
            CORE.Window.context = EGL_NO_CONTEXT;
        }

        eglTerminate(CORE.Window.device);
        CORE.Window.device = EGL_NO_DISPLAY;
    }



    
    
    

    CORE.Window.shouldClose = true;   

    
    if (CORE.Input.Keyboard.fd != -1)
    {
        close(CORE.Input.Keyboard.fd);
        CORE.Input.Keyboard.fd = -1;
    }

    for (int i = 0; i < sizeof(CORE.Input.eventWorker)/sizeof(InputEventWorker); ++i)
    {
        if (CORE.Input.eventWorker[i].threadId)
        {
            pthread_join(CORE.Input.eventWorker[i].threadId, NULL);
        }
    }

    if (CORE.Input.Gamepad.threadId) pthread_join(CORE.Input.Gamepad.threadId, NULL);



    free(events);


    CORE.Window.ready = false;
    TRACELOG(LOG_INFO, "Window closed successfully");
}


bool WindowShouldClose(void)
{

    
    
    
    
    
    emscripten_sleep(16);
    return false;



    if (CORE.Window.ready)
    {
        
        while (IsWindowState(FLAG_WINDOW_MINIMIZED) && !IsWindowState(FLAG_WINDOW_ALWAYS_RUN)) glfwWaitEvents();

        CORE.Window.shouldClose = glfwWindowShouldClose(CORE.Window.handle);

        
        glfwSetWindowShouldClose(CORE.Window.handle, GLFW_FALSE);

        return CORE.Window.shouldClose;
    }
    else return true;



    if (CORE.Window.ready) return CORE.Window.shouldClose;
    else return true;

}


bool IsWindowReady(void)
{
    return CORE.Window.ready;
}


bool IsWindowFullscreen(void)
{
    return CORE.Window.fullscreen;
}


bool IsWindowHidden(void)
{

    return ((CORE.Window.flags & FLAG_WINDOW_HIDDEN) > 0);

    return false;
}


bool IsWindowMinimized(void)
{

    return ((CORE.Window.flags & FLAG_WINDOW_MINIMIZED) > 0);

    return false;
}


bool IsWindowMaximized(void)
{

    return ((CORE.Window.flags & FLAG_WINDOW_MAXIMIZED) > 0);

    return false;
}


bool IsWindowFocused(void)
{

    return ((CORE.Window.flags & FLAG_WINDOW_UNFOCUSED) == 0);


    return CORE.Android.appEnabled;

    return true;
}


bool IsWindowResized(void)
{

    return CORE.Window.resizedLastFrame;

    return false;

}


bool IsWindowState(unsigned int flag)
{
    return ((CORE.Window.flags & flag) > 0);
}


void ToggleFullscreen(void)
{

    if (!CORE.Window.fullscreen)
    {
        
        glfwGetWindowPos(CORE.Window.handle, &CORE.Window.position.x, &CORE.Window.position.y);

        int monitorCount = 0;
        int monitorIndex = GetCurrentMonitor();
        GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

        
        GLFWmonitor *monitor = (monitorIndex < monitorCount)? monitors[monitorIndex] : NULL;

        if (monitor == NULL)
        {
            TRACELOG(LOG_WARNING, "GLFW: Failed to get monitor");

            CORE.Window.fullscreen = false;
            CORE.Window.flags &= ~FLAG_FULLSCREEN_MODE;

            glfwSetWindowMonitor(CORE.Window.handle, NULL, 0, 0, CORE.Window.screen.width, CORE.Window.screen.height, GLFW_DONT_CARE);
        }
        else {
            CORE.Window.fullscreen = true;
            CORE.Window.flags |= FLAG_FULLSCREEN_MODE;

            glfwSetWindowMonitor(CORE.Window.handle, monitor, 0, 0, CORE.Window.screen.width, CORE.Window.screen.height, GLFW_DONT_CARE);
        }
    }
    else {
        CORE.Window.fullscreen = false;
        CORE.Window.flags &= ~FLAG_FULLSCREEN_MODE;

        glfwSetWindowMonitor(CORE.Window.handle, NULL, CORE.Window.position.x, CORE.Window.position.y, CORE.Window.screen.width, CORE.Window.screen.height, GLFW_DONT_CARE);
    }

    
    
    if (CORE.Window.flags & FLAG_VSYNC_HINT) glfwSwapInterval(1);



    


    CORE.Window.fullscreen = !CORE.Window.fullscreen;          


    TRACELOG(LOG_WARNING, "SYSTEM: Failed to toggle to windowed mode");

}


void MaximizeWindow(void)
{

    if (glfwGetWindowAttrib(CORE.Window.handle, GLFW_RESIZABLE) == GLFW_TRUE)
    {
        glfwMaximizeWindow(CORE.Window.handle);
        CORE.Window.flags |= FLAG_WINDOW_MAXIMIZED;
    }

}


void MinimizeWindow(void)
{

    
    glfwIconifyWindow(CORE.Window.handle);

}


void RestoreWindow(void)
{

    if (glfwGetWindowAttrib(CORE.Window.handle, GLFW_RESIZABLE) == GLFW_TRUE)
    {
        
        glfwRestoreWindow(CORE.Window.handle);
        CORE.Window.flags &= ~FLAG_WINDOW_MINIMIZED;
        CORE.Window.flags &= ~FLAG_WINDOW_MAXIMIZED;
    }

}


void SetWindowState(unsigned int flags)
{

    
    

    
    if (((CORE.Window.flags & FLAG_VSYNC_HINT) != (flags & FLAG_VSYNC_HINT)) && ((flags & FLAG_VSYNC_HINT) > 0))
    {
        glfwSwapInterval(1);
        CORE.Window.flags |= FLAG_VSYNC_HINT;
    }

    
    if ((CORE.Window.flags & FLAG_FULLSCREEN_MODE) != (flags & FLAG_FULLSCREEN_MODE))
    {
        ToggleFullscreen();     
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_RESIZABLE) != (flags & FLAG_WINDOW_RESIZABLE)) && ((flags & FLAG_WINDOW_RESIZABLE) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_RESIZABLE, GLFW_TRUE);
        CORE.Window.flags |= FLAG_WINDOW_RESIZABLE;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_UNDECORATED) != (flags & FLAG_WINDOW_UNDECORATED)) && (flags & FLAG_WINDOW_UNDECORATED))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_DECORATED, GLFW_FALSE);
        CORE.Window.flags |= FLAG_WINDOW_UNDECORATED;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_HIDDEN) != (flags & FLAG_WINDOW_HIDDEN)) && ((flags & FLAG_WINDOW_HIDDEN) > 0))
    {
        glfwHideWindow(CORE.Window.handle);
        CORE.Window.flags |= FLAG_WINDOW_HIDDEN;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_MINIMIZED) != (flags & FLAG_WINDOW_MINIMIZED)) && ((flags & FLAG_WINDOW_MINIMIZED) > 0))
    {
        
        MinimizeWindow();       
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_MAXIMIZED) != (flags & FLAG_WINDOW_MAXIMIZED)) && ((flags & FLAG_WINDOW_MAXIMIZED) > 0))
    {
        
        MaximizeWindow();       
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_UNFOCUSED) != (flags & FLAG_WINDOW_UNFOCUSED)) && ((flags & FLAG_WINDOW_UNFOCUSED) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_FOCUS_ON_SHOW, GLFW_FALSE);
        CORE.Window.flags |= FLAG_WINDOW_UNFOCUSED;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_TOPMOST) != (flags & FLAG_WINDOW_TOPMOST)) && ((flags & FLAG_WINDOW_TOPMOST) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_FLOATING, GLFW_TRUE);
        CORE.Window.flags |= FLAG_WINDOW_TOPMOST;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_ALWAYS_RUN) != (flags & FLAG_WINDOW_ALWAYS_RUN)) && ((flags & FLAG_WINDOW_ALWAYS_RUN) > 0))
    {
        CORE.Window.flags |= FLAG_WINDOW_ALWAYS_RUN;
    }

    

    
    if (((CORE.Window.flags & FLAG_WINDOW_TRANSPARENT) != (flags & FLAG_WINDOW_TRANSPARENT)) && ((flags & FLAG_WINDOW_TRANSPARENT) > 0))
    {
        TRACELOG(LOG_WARNING, "WINDOW: Framebuffer transparency can only be configured before window initialization");
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) != (flags & FLAG_WINDOW_HIGHDPI)) && ((flags & FLAG_WINDOW_HIGHDPI) > 0))
    {
        TRACELOG(LOG_WARNING, "WINDOW: High DPI can only be configured before window initialization");
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_MOUSE_PASSTHROUGH) != (flags & FLAG_WINDOW_MOUSE_PASSTHROUGH)) && ((flags & FLAG_WINDOW_MOUSE_PASSTHROUGH) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_MOUSE_PASSTHROUGH, GLFW_TRUE);
        CORE.Window.flags |= FLAG_WINDOW_MOUSE_PASSTHROUGH;
    }

    
    if (((CORE.Window.flags & FLAG_MSAA_4X_HINT) != (flags & FLAG_MSAA_4X_HINT)) && ((flags & FLAG_MSAA_4X_HINT) > 0))
    {
        TRACELOG(LOG_WARNING, "WINDOW: MSAA can only be configured before window initialization");
    }

    
    if (((CORE.Window.flags & FLAG_INTERLACED_HINT) != (flags & FLAG_INTERLACED_HINT)) && ((flags & FLAG_INTERLACED_HINT) > 0))
    {
        TRACELOG(LOG_WARNING, "RPI: Interlaced mode can only be configured before window initialization");
    }

}


void ClearWindowState(unsigned int flags)
{

    
    

    
    if (((CORE.Window.flags & FLAG_VSYNC_HINT) > 0) && ((flags & FLAG_VSYNC_HINT) > 0))
    {
        glfwSwapInterval(0);
        CORE.Window.flags &= ~FLAG_VSYNC_HINT;
    }

    
    if (((CORE.Window.flags & FLAG_FULLSCREEN_MODE) > 0) && ((flags & FLAG_FULLSCREEN_MODE) > 0))
    {
        ToggleFullscreen();     
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_RESIZABLE) > 0) && ((flags & FLAG_WINDOW_RESIZABLE) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_RESIZABLE, GLFW_FALSE);
        CORE.Window.flags &= ~FLAG_WINDOW_RESIZABLE;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_UNDECORATED) > 0) && ((flags & FLAG_WINDOW_UNDECORATED) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_DECORATED, GLFW_TRUE);
        CORE.Window.flags &= ~FLAG_WINDOW_UNDECORATED;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_HIDDEN) > 0) && ((flags & FLAG_WINDOW_HIDDEN) > 0))
    {
        glfwShowWindow(CORE.Window.handle);
        CORE.Window.flags &= ~FLAG_WINDOW_HIDDEN;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_MINIMIZED) > 0) && ((flags & FLAG_WINDOW_MINIMIZED) > 0))
    {
        RestoreWindow();       
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_MAXIMIZED) > 0) && ((flags & FLAG_WINDOW_MAXIMIZED) > 0))
    {
        RestoreWindow();       
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_UNFOCUSED) > 0) && ((flags & FLAG_WINDOW_UNFOCUSED) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_FOCUS_ON_SHOW, GLFW_TRUE);
        CORE.Window.flags &= ~FLAG_WINDOW_UNFOCUSED;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_TOPMOST) > 0) && ((flags & FLAG_WINDOW_TOPMOST) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_FLOATING, GLFW_FALSE);
        CORE.Window.flags &= ~FLAG_WINDOW_TOPMOST;
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_ALWAYS_RUN) > 0) && ((flags & FLAG_WINDOW_ALWAYS_RUN) > 0))
    {
        CORE.Window.flags &= ~FLAG_WINDOW_ALWAYS_RUN;
    }

    

    
    if (((CORE.Window.flags & FLAG_WINDOW_TRANSPARENT) > 0) && ((flags & FLAG_WINDOW_TRANSPARENT) > 0))
    {
        TRACELOG(LOG_WARNING, "WINDOW: Framebuffer transparency can only be configured before window initialization");
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) > 0) && ((flags & FLAG_WINDOW_HIGHDPI) > 0))
    {
        TRACELOG(LOG_WARNING, "WINDOW: High DPI can only be configured before window initialization");
    }

    
    if (((CORE.Window.flags & FLAG_WINDOW_MOUSE_PASSTHROUGH) > 0) && ((flags & FLAG_WINDOW_MOUSE_PASSTHROUGH) > 0))
    {
        glfwSetWindowAttrib(CORE.Window.handle, GLFW_MOUSE_PASSTHROUGH, GLFW_FALSE);
        CORE.Window.flags &= ~FLAG_WINDOW_MOUSE_PASSTHROUGH;
    }

    
    if (((CORE.Window.flags & FLAG_MSAA_4X_HINT) > 0) && ((flags & FLAG_MSAA_4X_HINT) > 0))
    {
        TRACELOG(LOG_WARNING, "WINDOW: MSAA can only be configured before window initialization");
    }

    
    if (((CORE.Window.flags & FLAG_INTERLACED_HINT) > 0) && ((flags & FLAG_INTERLACED_HINT) > 0))
    {
        TRACELOG(LOG_WARNING, "RPI: Interlaced mode can only be configured before window initialization");
    }

}




void SetWindowIcon(Image image)
{

    if (image.data == NULL)
    {
        
        glfwSetWindowIcon(CORE.Window.handle, 0, NULL);
    }
    else {
        if (image.format == PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
        {
            GLFWimage icon[1] = { 0 };

            icon[0].width = image.width;
            icon[0].height = image.height;
            icon[0].pixels = (unsigned char *)image.data;

            
            
            glfwSetWindowIcon(CORE.Window.handle, 1, icon);
        }
        else TRACELOG(LOG_WARNING, "GLFW: Window icon image must be in R8G8B8A8 pixel format");
    }

}





void SetWindowIcons(Image *images, int count)
{

    if ((images == NULL) || (count <= 0))
    {
        
        glfwSetWindowIcon(CORE.Window.handle, 0, NULL);
    }
    else {
        int valid = 0;
        GLFWimage *icons = RL_CALLOC(count, sizeof(GLFWimage));

        for (int i = 0; i < count; i++)
        {
            if (images[i].format == PIXELFORMAT_UNCOMPRESSED_R8G8B8A8)
            {
                icons[valid].width = images[i].width;
                icons[valid].height = images[i].height;
                icons[valid].pixels = (unsigned char *)images[i].data;

                valid++;
            }
            else TRACELOG(LOG_WARNING, "GLFW: Window icon image must be in R8G8B8A8 pixel format");
        }
        
        glfwSetWindowIcon(CORE.Window.handle, valid, icons);

        RL_FREE(icons);
    }

}


void SetWindowTitle(const char *title)
{
    CORE.Window.title = title;

    glfwSetWindowTitle(CORE.Window.handle, title);

}


void SetWindowPosition(int x, int y)
{

    glfwSetWindowPos(CORE.Window.handle, x, y);

}


void SetWindowMonitor(int monitor)
{

    int monitorCount = 0;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        TRACELOG(LOG_INFO, "GLFW: Selected fullscreen monitor: [%i] %s", monitor, glfwGetMonitorName(monitors[monitor]));

        const GLFWvidmode *mode = glfwGetVideoMode(monitors[monitor]);
        glfwSetWindowMonitor(CORE.Window.handle, monitors[monitor], 0, 0, mode->width, mode->height, mode->refreshRate);
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");

}


void SetWindowMinSize(int width, int height)
{

    const GLFWvidmode *mode = glfwGetVideoMode(glfwGetPrimaryMonitor());
    glfwSetWindowSizeLimits(CORE.Window.handle, width, height, mode->width, mode->height);

}


void SetWindowSize(int width, int height)
{

    glfwSetWindowSize(CORE.Window.handle, width, height);

}


void SetWindowOpacity(float opacity)
{

    if (opacity >= 1.0f) opacity = 1.0f;
    else if (opacity <= 0.0f) opacity = 0.0f;
    glfwSetWindowOpacity(CORE.Window.handle, opacity);

}


int GetScreenWidth(void)
{
    return CORE.Window.screen.width;
}


int GetScreenHeight(void)
{
    return CORE.Window.screen.height;
}


int GetRenderWidth(void)
{
    return CORE.Window.render.width;
}


int GetRenderHeight(void)
{
    return CORE.Window.render.height;
}


void *GetWindowHandle(void)
{

    
    return glfwGetWin32Window(CORE.Window.handle);


    
    
    
    
    
    return (void *)CORE.Window.handle;


    
    return (void *)glfwGetCocoaWindow(CORE.Window.handle);


    return NULL;
}


int GetMonitorCount(void)
{

    int monitorCount;
    glfwGetMonitors(&monitorCount);
    return monitorCount;

    return 1;

}


int GetCurrentMonitor(void)
{
    int index = 0;


    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);
    GLFWmonitor *monitor = NULL;

    if (monitorCount > 1)
    {
        if (IsWindowFullscreen())
        {
            
            monitor = glfwGetWindowMonitor(CORE.Window.handle);

            for (int i = 0; i < monitorCount; i++)
            {
                if (monitors[i] == monitor)
                {
                    index = i;
                    break;
                }
            }
        }
        else {
            int x = 0;
            int y = 0;

            glfwGetWindowPos(CORE.Window.handle, &x, &y);

            for (int i = 0; i < monitorCount; i++)
            {
                int mx = 0;
                int my = 0;

                int width = 0;
                int height = 0;

                monitor = monitors[i];
                glfwGetMonitorWorkarea(monitor, &mx, &my, &width, &height);

                if (x >= mx && x <= (mx + width) && y >= my && y <= (my + height))
                {
                    index = i;
                    break;
                }
            }
        }
    }


    return index;
}


Vector2 GetMonitorPosition(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        int x, y;
        glfwGetMonitorPos(monitors[monitor], &x, &y);

        return (Vector2){ (float)x, (float)y };
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");

    return (Vector2){ 0, 0 };
}


int GetMonitorWidth(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        const GLFWvidmode *mode = glfwGetVideoMode(monitors[monitor]);

        if (mode) return mode->width;
        else TRACELOG(LOG_WARNING, "GLFW: Failed to find video mode for selected monitor");
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");


    if (CORE.Android.app->window != NULL)
    {
        return ANativeWindow_getWidth(CORE.Android.app->window);
    }

    return 0;
}


int GetMonitorHeight(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        const GLFWvidmode *mode = glfwGetVideoMode(monitors[monitor]);

        if (mode) return mode->height;
        else TRACELOG(LOG_WARNING, "GLFW: Failed to find video mode for selected monitor");
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");


    if (CORE.Android.app->window != NULL)
    {
        return ANativeWindow_getHeight(CORE.Android.app->window);
    }

    return 0;
}


int GetMonitorPhysicalWidth(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        int physicalWidth;
        glfwGetMonitorPhysicalSize(monitors[monitor], &physicalWidth, NULL);
        return physicalWidth;
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");

    return 0;
}


int GetMonitorPhysicalHeight(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        int physicalHeight;
        glfwGetMonitorPhysicalSize(monitors[monitor], NULL, &physicalHeight);
        return physicalHeight;
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");

    return 0;
}


int GetMonitorRefreshRate(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        const GLFWvidmode *vidmode = glfwGetVideoMode(monitors[monitor]);
        return vidmode->refreshRate;
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");


    if ((CORE.Window.connector) && (CORE.Window.modeIndex >= 0))
    {
        return CORE.Window.connector->modes[CORE.Window.modeIndex].vrefresh;
    }

    return 0;
}


Vector2 GetWindowPosition(void)
{
    int x = 0;
    int y = 0;

    glfwGetWindowPos(CORE.Window.handle, &x, &y);

    return (Vector2){ (float)x, (float)y };
}


Vector2 GetWindowScaleDPI(void)
{
    Vector2 scale = { 1.0f, 1.0f };


    float xdpi = 1.0;
    float ydpi = 1.0;
    Vector2 windowPos = GetWindowPosition();

    int monitorCount = 0;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    
    for (int i = 0; i < monitorCount; i++)
    {
        glfwGetMonitorContentScale(monitors[i], &xdpi, &ydpi);

        int xpos, ypos, width, height;
        glfwGetMonitorWorkarea(monitors[i], &xpos, &ypos, &width, &height);

        if ((windowPos.x >= xpos) && (windowPos.x < xpos + width) && (windowPos.y >= ypos) && (windowPos.y < ypos + height))
        {
            scale.x = xdpi;
            scale.y = ydpi;
            break;
        }
    }


    return scale;
}


const char *GetMonitorName(int monitor)
{

    int monitorCount;
    GLFWmonitor **monitors = glfwGetMonitors(&monitorCount);

    if ((monitor >= 0) && (monitor < monitorCount))
    {
        return glfwGetMonitorName(monitors[monitor]);
    }
    else TRACELOG(LOG_WARNING, "GLFW: Failed to find selected monitor");

    return "";
}


void SetClipboardText(const char *text)
{

    glfwSetClipboardString(CORE.Window.handle, text);


    emscripten_run_script(TextFormat("navigator.clipboard.writeText('%s')", text));

}



const char *GetClipboardText(void)
{

    return glfwGetClipboardString(CORE.Window.handle);


    
    
    
    emscripten_run_script_string("navigator.clipboard.readText()  .then(text => { document.getElementById('clipboard').innerText = text; console.log('Pasted content: ', text); }) .catch(err => { console.error('Failed to read clipboard contents: ', err); });

    );

    
    

    
    

    return NULL;

    return NULL;
}


void EnableEventWaiting(void)
{
    CORE.Window.eventWaiting = true;
}


void DisableEventWaiting(void)
{
    CORE.Window.eventWaiting = false;
}


void ShowCursor(void)
{

    glfwSetInputMode(CORE.Window.handle, GLFW_CURSOR, GLFW_CURSOR_NORMAL);


    CORE.Input.Mouse.cursorHidden = false;
}


void HideCursor(void)
{

    glfwSetInputMode(CORE.Window.handle, GLFW_CURSOR, GLFW_CURSOR_HIDDEN);


    CORE.Input.Mouse.cursorHidden = true;
}


bool IsCursorHidden(void)
{
    return CORE.Input.Mouse.cursorHidden;
}


void EnableCursor(void)
{

    glfwSetInputMode(CORE.Window.handle, GLFW_CURSOR, GLFW_CURSOR_NORMAL);


    emscripten_exit_pointerlock();

    
    SetMousePosition(CORE.Window.screen.width/2, CORE.Window.screen.height/2);

    CORE.Input.Mouse.cursorHidden = false;
}


void DisableCursor(void)
{

    glfwSetInputMode(CORE.Window.handle, GLFW_CURSOR, GLFW_CURSOR_DISABLED);


    emscripten_request_pointerlock("#canvas", 1);

    
    SetMousePosition(CORE.Window.screen.width/2, CORE.Window.screen.height/2);

    CORE.Input.Mouse.cursorHidden = true;
}


bool IsCursorOnScreen(void)
{
    return CORE.Input.Mouse.cursorOnScreen;
}


void ClearBackground(Color color)
{
    rlClearColor(color.r, color.g, color.b, color.a);   
    rlClearScreenBuffers();                             
}


void BeginDrawing(void)
{
    
    

    CORE.Time.current = GetTime();      
    CORE.Time.update = CORE.Time.current - CORE.Time.previous;
    CORE.Time.previous = CORE.Time.current;

    rlLoadIdentity();                   
    rlMultMatrixf(MatrixToFloat(CORE.Window.screenScale)); 

    
                                        
}


void EndDrawing(void)
{
    rlDrawRenderBatchActive();      


    
    if (gifRecording)
    {
        #define GIF_RECORD_FRAMERATE    10
        gifFrameCounter++;

        
        if ((gifFrameCounter%GIF_RECORD_FRAMERATE) == 0)
        {
            
            
            Vector2 scale = GetWindowScaleDPI();
            unsigned char *screenData = rlReadScreenPixels((int)((float)CORE.Window.render.width*scale.x), (int)((float)CORE.Window.render.height*scale.y));
            msf_gif_frame(&gifState, screenData, 10, 16, (int)((float)CORE.Window.render.width*scale.x)*4);

            RL_FREE(screenData);    
        }

    #if defined(SUPPORT_MODULE_RSHAPES) && defined(SUPPORT_MODULE_RTEXT)
        if (((gifFrameCounter/15)%2) == 1)
        {
            DrawCircle(30, CORE.Window.screen.height - 20, 10, MAROON);                 
            DrawText("GIF RECORDING", 50, CORE.Window.screen.height - 25, 10, RED);     
        }
    #endif

        rlDrawRenderBatchActive();  
    }



    
    if (eventsRecording)
    {
        gifFrameCounter++;

        if (((gifFrameCounter/15)%2) == 1)
        {
            DrawCircle(30, CORE.Window.screen.height - 20, 10, MAROON);
            DrawText("EVENTS RECORDING", 50, CORE.Window.screen.height - 25, 10, RED);
        }

        rlDrawRenderBatchActive();  
    }
    else if (eventsPlaying)
    {
        gifFrameCounter++;

        if (((gifFrameCounter/15)%2) == 1)
        {
            DrawCircle(30, CORE.Window.screen.height - 20, 10, LIME);
            DrawText("EVENTS PLAYING", 50, CORE.Window.screen.height - 25, 10, GREEN);
        }

        rlDrawRenderBatchActive();  
    }



    SwapScreenBuffer();                  

    
    CORE.Time.current = GetTime();
    CORE.Time.draw = CORE.Time.current - CORE.Time.previous;
    CORE.Time.previous = CORE.Time.current;

    CORE.Time.frame = CORE.Time.update + CORE.Time.draw;

    
    if (CORE.Time.frame < CORE.Time.target)
    {
        WaitTime(CORE.Time.target - CORE.Time.frame);

        CORE.Time.current = GetTime();
        double waitTime = CORE.Time.current - CORE.Time.previous;
        CORE.Time.previous = CORE.Time.current;

        CORE.Time.frame += waitTime;    
    }

    PollInputEvents();      



    
    if (eventsRecording) RecordAutomationEvent(CORE.Time.frameCounter);
    else if (eventsPlaying)
    {
        
        if (CORE.Time.frameCounter >= eventCount) eventsPlaying = false;
        PlayAutomationEvent(CORE.Time.frameCounter);
    }


    CORE.Time.frameCounter++;
}


void BeginMode2D(Camera2D camera)
{
    rlDrawRenderBatchActive();      

    rlLoadIdentity();               

    
    rlMultMatrixf(MatrixToFloat(GetCameraMatrix2D(camera)));

    
    rlMultMatrixf(MatrixToFloat(CORE.Window.screenScale));
}


void EndMode2D(void)
{
    rlDrawRenderBatchActive();      

    rlLoadIdentity();               
    rlMultMatrixf(MatrixToFloat(CORE.Window.screenScale)); 
}


void BeginMode3D(Camera camera)
{
    rlDrawRenderBatchActive();      

    rlMatrixMode(RL_PROJECTION);    
    rlPushMatrix();                 
    rlLoadIdentity();               

    float aspect = (float)CORE.Window.currentFbo.width/(float)CORE.Window.currentFbo.height;

    
    if (camera.projection == CAMERA_PERSPECTIVE)
    {
        
        double top = RL_CULL_DISTANCE_NEAR*tan(camera.fovy*0.5*DEG2RAD);
        double right = top*aspect;

        rlFrustum(-right, right, -top, top, RL_CULL_DISTANCE_NEAR, RL_CULL_DISTANCE_FAR);
    }
    else if (camera.projection == CAMERA_ORTHOGRAPHIC)
    {
        
        double top = camera.fovy/2.0;
        double right = top*aspect;

        rlOrtho(-right, right, -top,top, RL_CULL_DISTANCE_NEAR, RL_CULL_DISTANCE_FAR);
    }

    rlMatrixMode(RL_MODELVIEW);     
    rlLoadIdentity();               

    
    Matrix matView = MatrixLookAt(camera.position, camera.target, camera.up);
    rlMultMatrixf(MatrixToFloat(matView));      

    rlEnableDepthTest();            
}


void EndMode3D(void)
{
    rlDrawRenderBatchActive();      

    rlMatrixMode(RL_PROJECTION);    
    rlPopMatrix();                  

    rlMatrixMode(RL_MODELVIEW);     
    rlLoadIdentity();               

    rlMultMatrixf(MatrixToFloat(CORE.Window.screenScale)); 

    rlDisableDepthTest();           
}


void BeginTextureMode(RenderTexture2D target)
{
    rlDrawRenderBatchActive();      

    rlEnableFramebuffer(target.id); 

    
    rlViewport(0, 0, target.texture.width, target.texture.height);
    rlSetFramebufferWidth(target.texture.width);
    rlSetFramebufferHeight(target.texture.height);

    rlMatrixMode(RL_PROJECTION);    
    rlLoadIdentity();               

    
    
    rlOrtho(0, target.texture.width, target.texture.height, 0, 0.0f, 1.0f);

    rlMatrixMode(RL_MODELVIEW);     
    rlLoadIdentity();               

    

    
    
    CORE.Window.currentFbo.width = target.texture.width;
    CORE.Window.currentFbo.height = target.texture.height;
}


void EndTextureMode(void)
{
    rlDrawRenderBatchActive();      

    rlDisableFramebuffer();         

    
    SetupViewport(CORE.Window.render.width, CORE.Window.render.height);

    
    CORE.Window.currentFbo.width = CORE.Window.render.width;
    CORE.Window.currentFbo.height = CORE.Window.render.height;
}


void BeginShaderMode(Shader shader)
{
    rlSetShader(shader.id, shader.locs);
}


void EndShaderMode(void)
{
    rlSetShader(rlGetShaderIdDefault(), rlGetShaderLocsDefault());
}



void BeginBlendMode(int mode)
{
    rlSetBlendMode(mode);
}


void EndBlendMode(void)
{
    rlSetBlendMode(BLEND_ALPHA);
}



void BeginScissorMode(int x, int y, int width, int height)
{
    rlDrawRenderBatchActive();      

    rlEnableScissorTest();


    Vector2 scale = GetWindowScaleDPI();
    rlScissor((int)(x*scale.x), (int)(GetScreenHeight()*scale.y - (((y + height)*scale.y))), (int)(width*scale.x), (int)(height*scale.y));

    if ((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) > 0)
    {
        Vector2 scale = GetWindowScaleDPI();
        rlScissor((int)(x*scale.x), (int)(CORE.Window.currentFbo.height - (y + height)*scale.y), (int)(width*scale.x), (int)(height*scale.y));
    }
    else {
        rlScissor(x, CORE.Window.currentFbo.height - (y + height), width, height);
    }

}


void EndScissorMode(void)
{
    rlDrawRenderBatchActive();      
    rlDisableScissorTest();
}


void BeginVrStereoMode(VrStereoConfig config)
{
    rlEnableStereoRender();

    
    rlSetMatrixProjectionStereo(config.projection[0], config.projection[1]);
    rlSetMatrixViewOffsetStereo(config.viewOffset[0], config.viewOffset[1]);
}


void EndVrStereoMode(void)
{
    rlDisableStereoRender();
}


VrStereoConfig LoadVrStereoConfig(VrDeviceInfo device)
{
    VrStereoConfig config = { 0 };

    if ((rlGetVersion() == RL_OPENGL_33) || (rlGetVersion() == RL_OPENGL_ES_20))
    {
        
        float aspect = ((float)device.hResolution*0.5f)/(float)device.vResolution;

        
        float lensShift = (device.hScreenSize*0.25f - device.lensSeparationDistance*0.5f)/device.hScreenSize;
        config.leftLensCenter[0] = 0.25f + lensShift;
        config.leftLensCenter[1] = 0.5f;
        config.rightLensCenter[0] = 0.75f - lensShift;
        config.rightLensCenter[1] = 0.5f;
        config.leftScreenCenter[0] = 0.25f;
        config.leftScreenCenter[1] = 0.5f;
        config.rightScreenCenter[0] = 0.75f;
        config.rightScreenCenter[1] = 0.5f;

        
        
        float lensRadius = fabsf(-1.0f - 4.0f*lensShift);
        float lensRadiusSq = lensRadius*lensRadius;
        float distortionScale = device.lensDistortionValues[0] + device.lensDistortionValues[1]*lensRadiusSq + device.lensDistortionValues[2]*lensRadiusSq*lensRadiusSq + device.lensDistortionValues[3]*lensRadiusSq*lensRadiusSq*lensRadiusSq;



        float normScreenWidth = 0.5f;
        float normScreenHeight = 1.0f;
        config.scaleIn[0] = 2.0f/normScreenWidth;
        config.scaleIn[1] = 2.0f/normScreenHeight/aspect;
        config.scale[0] = normScreenWidth*0.5f/distortionScale;
        config.scale[1] = normScreenHeight*0.5f*aspect/distortionScale;

        
        
        float fovy = 2.0f*atan2f(device.vScreenSize*0.5f*distortionScale, device.eyeToScreenDistance);     
       

        
        float projOffset = 4.0f*lensShift;      
        Matrix proj = MatrixPerspective(fovy, aspect, RL_CULL_DISTANCE_NEAR, RL_CULL_DISTANCE_FAR);

        config.projection[0] = MatrixMultiply(proj, MatrixTranslate(projOffset, 0.0f, 0.0f));
        config.projection[1] = MatrixMultiply(proj, MatrixTranslate(-projOffset, 0.0f, 0.0f));

        
        
        
        
        config.viewOffset[0] = MatrixTranslate(-device.interpupillaryDistance*0.5f, 0.075f, 0.045f);
        config.viewOffset[1] = MatrixTranslate(device.interpupillaryDistance*0.5f, 0.075f, 0.045f);

        
        
    }
    else TRACELOG(LOG_WARNING, "RLGL: VR Simulator not supported on OpenGL 1.1");

    return config;
}


void UnloadVrStereoConfig(VrStereoConfig config)
{
    
}



Shader LoadShader(const char *vsFileName, const char *fsFileName)
{
    Shader shader = { 0 };

    char *vShaderStr = NULL;
    char *fShaderStr = NULL;

    if (vsFileName != NULL) vShaderStr = LoadFileText(vsFileName);
    if (fsFileName != NULL) fShaderStr = LoadFileText(fsFileName);

    shader = LoadShaderFromMemory(vShaderStr, fShaderStr);

    UnloadFileText(vShaderStr);
    UnloadFileText(fShaderStr);

    return shader;
}


Shader LoadShaderFromMemory(const char *vsCode, const char *fsCode)
{
    Shader shader = { 0 };

    shader.id = rlLoadShaderCode(vsCode, fsCode);

    
    if (shader.id > 0)
    {
        
        
        
        
        
        
        

        

        shader.locs = (int *)RL_CALLOC(RL_MAX_SHADER_LOCATIONS, sizeof(int));

        
        for (int i = 0; i < RL_MAX_SHADER_LOCATIONS; i++) shader.locs[i] = -1;

        
        shader.locs[SHADER_LOC_VERTEX_POSITION] = rlGetLocationAttrib(shader.id, RL_DEFAULT_SHADER_ATTRIB_NAME_POSITION);
        shader.locs[SHADER_LOC_VERTEX_TEXCOORD01] = rlGetLocationAttrib(shader.id, RL_DEFAULT_SHADER_ATTRIB_NAME_TEXCOORD);
        shader.locs[SHADER_LOC_VERTEX_TEXCOORD02] = rlGetLocationAttrib(shader.id, RL_DEFAULT_SHADER_ATTRIB_NAME_TEXCOORD2);
        shader.locs[SHADER_LOC_VERTEX_NORMAL] = rlGetLocationAttrib(shader.id, RL_DEFAULT_SHADER_ATTRIB_NAME_NORMAL);
        shader.locs[SHADER_LOC_VERTEX_TANGENT] = rlGetLocationAttrib(shader.id, RL_DEFAULT_SHADER_ATTRIB_NAME_TANGENT);
        shader.locs[SHADER_LOC_VERTEX_COLOR] = rlGetLocationAttrib(shader.id, RL_DEFAULT_SHADER_ATTRIB_NAME_COLOR);

        
        shader.locs[SHADER_LOC_MATRIX_MVP] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_UNIFORM_NAME_MVP);
        shader.locs[SHADER_LOC_MATRIX_VIEW] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_UNIFORM_NAME_VIEW);
        shader.locs[SHADER_LOC_MATRIX_PROJECTION] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_UNIFORM_NAME_PROJECTION);
        shader.locs[SHADER_LOC_MATRIX_MODEL] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_UNIFORM_NAME_MODEL);
        shader.locs[SHADER_LOC_MATRIX_NORMAL] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_UNIFORM_NAME_NORMAL);

        
        shader.locs[SHADER_LOC_COLOR_DIFFUSE] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_UNIFORM_NAME_COLOR);
        shader.locs[SHADER_LOC_MAP_DIFFUSE] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_SAMPLER2D_NAME_TEXTURE0);  
        shader.locs[SHADER_LOC_MAP_SPECULAR] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_SAMPLER2D_NAME_TEXTURE1); 
        shader.locs[SHADER_LOC_MAP_NORMAL] = rlGetLocationUniform(shader.id, RL_DEFAULT_SHADER_SAMPLER2D_NAME_TEXTURE2);
    }

    return shader;
}


bool IsShaderReady(Shader shader)
{
    return ((shader.id > 0) &&           (shader.locs != NULL));

    
    
    

    
    
    
    
    
    
    

    
    
    
    
    
    

    
    
    
    
    
}


void UnloadShader(Shader shader)
{
    if (shader.id != rlGetShaderIdDefault())
    {
        rlUnloadShaderProgram(shader.id);

        
        RL_FREE(shader.locs);
    }
}


int GetShaderLocation(Shader shader, const char *uniformName)
{
    return rlGetLocationUniform(shader.id, uniformName);
}


int GetShaderLocationAttrib(Shader shader, const char *attribName)
{
    return rlGetLocationAttrib(shader.id, attribName);
}


void SetShaderValue(Shader shader, int locIndex, const void *value, int uniformType)
{
    SetShaderValueV(shader, locIndex, value, uniformType, 1);
}


void SetShaderValueV(Shader shader, int locIndex, const void *value, int uniformType, int count)
{
    if (locIndex > -1)
    {
        rlEnableShader(shader.id);
        rlSetUniform(locIndex, value, uniformType, count);
        
    }
}


void SetShaderValueMatrix(Shader shader, int locIndex, Matrix mat)
{
    if (locIndex > -1)
    {
        rlEnableShader(shader.id);
        rlSetUniformMatrix(locIndex, mat);
        
    }
}


void SetShaderValueTexture(Shader shader, int locIndex, Texture2D texture)
{
    if (locIndex > -1)
    {
        rlEnableShader(shader.id);
        rlSetUniformSampler(locIndex, texture.id);
        
    }
}


Ray GetMouseRay(Vector2 mouse, Camera camera)
{
    Ray ray = { 0 };

    
    
    float x = (2.0f*mouse.x)/(float)GetScreenWidth() - 1.0f;
    float y = 1.0f - (2.0f*mouse.y)/(float)GetScreenHeight();
    float z = 1.0f;

    
    Vector3 deviceCoords = { x, y, z };

    
    Matrix matView = MatrixLookAt(camera.position, camera.target, camera.up);

    Matrix matProj = MatrixIdentity();

    if (camera.projection == CAMERA_PERSPECTIVE)
    {
        
        matProj = MatrixPerspective(camera.fovy*DEG2RAD, ((double)GetScreenWidth()/(double)GetScreenHeight()), RL_CULL_DISTANCE_NEAR, RL_CULL_DISTANCE_FAR);
    }
    else if (camera.projection == CAMERA_ORTHOGRAPHIC)
    {
        float aspect = (float)CORE.Window.screen.width/(float)CORE.Window.screen.height;
        double top = camera.fovy/2.0;
        double right = top*aspect;

        
        matProj = MatrixOrtho(-right, right, -top, top, 0.01, 1000.0);
    }

    
    Vector3 nearPoint = Vector3Unproject((Vector3){ deviceCoords.x, deviceCoords.y, 0.0f }, matProj, matView);
    Vector3 farPoint = Vector3Unproject((Vector3){ deviceCoords.x, deviceCoords.y, 1.0f }, matProj, matView);

    
    
    
    Vector3 cameraPlanePointerPos = Vector3Unproject((Vector3){ deviceCoords.x, deviceCoords.y, -1.0f }, matProj, matView);

    
    Vector3 direction = Vector3Normalize(Vector3Subtract(farPoint, nearPoint));

    if (camera.projection == CAMERA_PERSPECTIVE) ray.position = camera.position;
    else if (camera.projection == CAMERA_ORTHOGRAPHIC) ray.position = cameraPlanePointerPos;

    
    ray.direction = direction;

    return ray;
}


Matrix GetCameraMatrix(Camera camera)
{
    return MatrixLookAt(camera.position, camera.target, camera.up);
}


Matrix GetCameraMatrix2D(Camera2D camera)
{
    Matrix matTransform = { 0 };
    
    
    
    
    
    
    
    

    
    
    
    
    
    Matrix matOrigin = MatrixTranslate(-camera.target.x, -camera.target.y, 0.0f);
    Matrix matRotation = MatrixRotate((Vector3){ 0.0f, 0.0f, 1.0f }, camera.rotation*DEG2RAD);
    Matrix matScale = MatrixScale(camera.zoom, camera.zoom, 1.0f);
    Matrix matTranslation = MatrixTranslate(camera.offset.x, camera.offset.y, 0.0f);

    matTransform = MatrixMultiply(MatrixMultiply(matOrigin, MatrixMultiply(matScale, matRotation)), matTranslation);

    return matTransform;
}


Vector2 GetWorldToScreen(Vector3 position, Camera camera)
{
    Vector2 screenPosition = GetWorldToScreenEx(position, camera, GetScreenWidth(), GetScreenHeight());

    return screenPosition;
}


Vector2 GetWorldToScreenEx(Vector3 position, Camera camera, int width, int height)
{
    
    Matrix matProj = MatrixIdentity();

    if (camera.projection == CAMERA_PERSPECTIVE)
    {
        
        matProj = MatrixPerspective(camera.fovy*DEG2RAD, ((double)width/(double)height), RL_CULL_DISTANCE_NEAR, RL_CULL_DISTANCE_FAR);
    }
    else if (camera.projection == CAMERA_ORTHOGRAPHIC)
    {
        float aspect = (float)CORE.Window.screen.width/(float)CORE.Window.screen.height;
        double top = camera.fovy/2.0;
        double right = top*aspect;

        
        matProj = MatrixOrtho(-right, right, -top, top, RL_CULL_DISTANCE_NEAR, RL_CULL_DISTANCE_FAR);
    }

    
    Matrix matView = MatrixLookAt(camera.position, camera.target, camera.up);

    

    
    Quaternion worldPos = { position.x, position.y, position.z, 1.0f };

    
    worldPos = QuaternionTransform(worldPos, matView);

    
    worldPos = QuaternionTransform(worldPos, matProj);

    
    Vector3 ndcPos = { worldPos.x/worldPos.w, -worldPos.y/worldPos.w, worldPos.z/worldPos.w };

    
    Vector2 screenPosition = { (ndcPos.x + 1.0f)/2.0f*(float)width, (ndcPos.y + 1.0f)/2.0f*(float)height };

    return screenPosition;
}


Vector2 GetWorldToScreen2D(Vector2 position, Camera2D camera)
{
    Matrix matCamera = GetCameraMatrix2D(camera);
    Vector3 transform = Vector3Transform((Vector3){ position.x, position.y, 0 }, matCamera);

    return (Vector2){ transform.x, transform.y };
}


Vector2 GetScreenToWorld2D(Vector2 position, Camera2D camera)
{
    Matrix invMatCamera = MatrixInvert(GetCameraMatrix2D(camera));
    Vector3 transform = Vector3Transform((Vector3){ position.x, position.y, 0 }, invMatCamera);

    return (Vector2){ transform.x, transform.y };
}


void SetTargetFPS(int fps)
{
    if (fps < 1) CORE.Time.target = 0.0;
    else CORE.Time.target = 1.0/(double)fps;

    TRACELOG(LOG_INFO, "TIMER: Target time per frame: %02.03f milliseconds", (float)CORE.Time.target*1000.0f);
}



int GetFPS(void)
{
    int fps = 0;


    #define FPS_CAPTURE_FRAMES_COUNT    30      
    #define FPS_AVERAGE_TIME_SECONDS   0.5f     
    #define FPS_STEP (FPS_AVERAGE_TIME_SECONDS/FPS_CAPTURE_FRAMES_COUNT)

    static int index = 0;
    static float history[FPS_CAPTURE_FRAMES_COUNT] = { 0 };
    static float average = 0, last = 0;
    float fpsFrame = GetFrameTime();

    if (fpsFrame == 0) return 0;

    if ((GetTime() - last) > FPS_STEP)
    {
        last = (float)GetTime();
        index = (index + 1)%FPS_CAPTURE_FRAMES_COUNT;
        average -= history[index];
        history[index] = fpsFrame/FPS_CAPTURE_FRAMES_COUNT;
        average += history[index];
    }

    fps = (int)roundf(1.0f/average);


    return fps;
}


float GetFrameTime(void)
{
    return (float)CORE.Time.frame;
}




double GetTime(void)
{
    double time = 0.0;

    time = glfwGetTime();   



    struct timespec ts = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long int nanoSeconds = (unsigned long long int)ts.tv_sec*1000000000LLU + (unsigned long long int)ts.tv_nsec;

    time = (double)(nanoSeconds - CORE.Time.base)*1e-9;  

    return time;
}





void SetConfigFlags(unsigned int flags)
{
    
    
    CORE.Window.flags |= flags;
}




void TakeScreenshot(const char *fileName)
{

    Vector2 scale = GetWindowScaleDPI();
    unsigned char *imgData = rlReadScreenPixels((int)((float)CORE.Window.render.width*scale.x), (int)((float)CORE.Window.render.height*scale.y));
    Image image = { imgData, (int)((float)CORE.Window.render.width*scale.x), (int)((float)CORE.Window.render.height*scale.y), 1, PIXELFORMAT_UNCOMPRESSED_R8G8B8A8 };

    char path[2048] = { 0 };
    strcpy(path, TextFormat("%s/%s", CORE.Storage.basePath, fileName));

    ExportImage(image, path);           
    RL_FREE(imgData);


    
    
    emscripten_run_script(TextFormat("saveFileFromMEMFSToDisk('%s','%s')", GetFileName(path), GetFileName(path)));


    TRACELOG(LOG_INFO, "SYSTEM: [%s] Screenshot taken successfully", path);

    TRACELOG(LOG_WARNING,"IMAGE: ExportImage() requires module: rtextures");

}





int GetRandomValue(int min, int max)
{
    if (min > max)
    {
        int tmp = max;
        max = min;
        min = tmp;
    }

    if ((unsigned int)(max - min) > (unsigned int)RAND_MAX)
    {
        TRACELOG(LOG_WARNING, "Invalid GetRandomValue() arguments, range should not be higher than %i", RAND_MAX);
    }

    return (rand()%(abs(max - min) + 1) + min);
}


void SetRandomSeed(unsigned int seed)
{
    srand(seed);
}


bool FileExists(const char *fileName)
{
    bool result = false;


    if (_access(fileName, 0) != -1) result = true;

    if (access(fileName, F_OK) != -1) result = true;


    
    
    
    

    return result;
}



bool IsFileExtension(const char *fileName, const char *ext)
{
    #define MAX_FILE_EXTENSION_SIZE  16

    bool result = false;
    const char *fileExt = GetFileExtension(fileName);

    if (fileExt != NULL)
    {

        int extCount = 0;
        const char **checkExts = TextSplit(ext, ';', &extCount);  

        char fileExtLower[MAX_FILE_EXTENSION_SIZE + 1] = { 0 };
        strncpy(fileExtLower, TextToLower(fileExt),MAX_FILE_EXTENSION_SIZE);  

        for (int i = 0; i < extCount; i++)
        {
            if (strcmp(fileExtLower, TextToLower(checkExts[i])) == 0)
            {
                result = true;
                break;
            }
        }

        if (strcmp(fileExt, ext) == 0) result = true;

    }

    return result;
}


bool DirectoryExists(const char *dirPath)
{
    bool result = false;
    DIR *dir = opendir(dirPath);

    if (dir != NULL)
    {
        result = true;
        closedir(dir);
    }

    return result;
}



int GetFileLength(const char *fileName)
{
    int size = 0;

    FILE *file = fopen(fileName, "rb");

    if (file != NULL)
    {
        fseek(file, 0L, SEEK_END);
        size = (int)ftell(file);
        fclose(file);
    }

    return size;
}


const char *GetFileExtension(const char *fileName)
{
    const char *dot = strrchr(fileName, '.');

    if (!dot || dot == fileName) return NULL;

    return dot;
}


static const char *strprbrk(const char *s, const char *charset)
{
    const char *latestMatch = NULL;
    for (; s = strpbrk(s, charset), s != NULL; latestMatch = s++) { }
    return latestMatch;
}


const char *GetFileName(const char *filePath)
{
    const char *fileName = NULL;
    if (filePath != NULL) fileName = strprbrk(filePath, "\\/");

    if (!fileName) return filePath;

    return fileName + 1;
}


const char *GetFileNameWithoutExt(const char *filePath)
{
    #define MAX_FILENAMEWITHOUTEXT_LENGTH   256

    static char fileName[MAX_FILENAMEWITHOUTEXT_LENGTH] = { 0 };
    memset(fileName, 0, MAX_FILENAMEWITHOUTEXT_LENGTH);

    if (filePath != NULL) strcpy(fileName, GetFileName(filePath));   

    int size = (int)strlen(fileName);   

    for (int i = 0; (i < size) && (i < MAX_FILENAMEWITHOUTEXT_LENGTH); i++)
    {
        if (fileName[i] == '.')
        {
            
            fileName[i] = '\0';
            break;
        }
    }

    return fileName;
}


const char *GetDirectoryPath(const char *filePath)
{

    const char *lastSlash = NULL;
    static char dirPath[MAX_FILEPATH_LENGTH] = { 0 };
    memset(dirPath, 0, MAX_FILEPATH_LENGTH);

    
    
    if (filePath[1] != ':' && filePath[0] != '\\' && filePath[0] != '/')
    {
        
        
        dirPath[0] = '.';
        dirPath[1] = '/';
    }

    lastSlash = strprbrk(filePath, "\\/");
    if (lastSlash)
    {
        if (lastSlash == filePath)
        {
            
            dirPath[0] = filePath[0];
            dirPath[1] = '\0';
        }
        else {
            
            memcpy(dirPath + (filePath[1] != ':' && filePath[0] != '\\' && filePath[0] != '/' ? 2 : 0), filePath, strlen(filePath) - (strlen(lastSlash) - 1));
            dirPath[strlen(filePath) - strlen(lastSlash) + (filePath[1] != ':' && filePath[0] != '\\' && filePath[0] != '/' ? 2 : 0)] = '\0';  
        }
    }

    return dirPath;
}


const char *GetPrevDirectoryPath(const char *dirPath)
{
    static char prevDirPath[MAX_FILEPATH_LENGTH] = { 0 };
    memset(prevDirPath, 0, MAX_FILEPATH_LENGTH);
    int pathLen = (int)strlen(dirPath);

    if (pathLen <= 3) strcpy(prevDirPath, dirPath);

    for (int i = (pathLen - 1); (i >= 0) && (pathLen > 3); i--)
    {
        if ((dirPath[i] == '\\') || (dirPath[i] == '/'))
        {
            
            if (((i == 2) && (dirPath[1] ==':')) || (i == 0)) i++;

            strncpy(prevDirPath, dirPath, i);
            break;
        }
    }

    return prevDirPath;
}


const char *GetWorkingDirectory(void)
{
    static char currentDir[MAX_FILEPATH_LENGTH] = { 0 };
    memset(currentDir, 0, MAX_FILEPATH_LENGTH);

    char *path = GETCWD(currentDir, MAX_FILEPATH_LENGTH - 1);

    return path;
}

const char *GetApplicationDirectory(void)
{
    static char appDir[MAX_FILEPATH_LENGTH] = { 0 };
    memset(appDir, 0, MAX_FILEPATH_LENGTH);


    int len = 0;

    unsigned short widePath[MAX_PATH];
    len = GetModuleFileNameW(NULL, widePath, MAX_PATH);
    len = WideCharToMultiByte(0, 0, widePath, len, appDir, MAX_PATH, NULL, NULL);

    len = GetModuleFileNameA(NULL, appDir, MAX_PATH);

    if (len > 0)
    {
        for (int i = len; i >= 0; --i)
        {
            if (appDir[i] == '\\')
            {
                appDir[i + 1] = '\0';
                break;
            }
        }
    }
    else {
        appDir[0] = '.';
        appDir[1] = '\\';
    }


    unsigned int size = sizeof(appDir);
    ssize_t len = readlink("/proc/self/exe", appDir, size);

    if (len > 0)
    {
        for (int i = len; i >= 0; --i)
        {
            if (appDir[i] == '/')
            {
                appDir[i + 1] = '\0';
                break;
            }
        }
    }
    else {
        appDir[0] = '.';
        appDir[1] = '/';
    }

    uint32_t size = sizeof(appDir);

    if (_NSGetExecutablePath(appDir, &size) == 0)
    {
        int len = strlen(appDir);
        for (int i = len; i >= 0; --i)
        {
            if (appDir[i] == '/')
            {
                appDir[i + 1] = '\0';
                break;
            }
        }
    }
    else {
        appDir[0] = '.';
        appDir[1] = '/';
    }


    return appDir;
}





FilePathList LoadDirectoryFiles(const char *dirPath)
{
    FilePathList files = { 0 };
    unsigned int fileCounter = 0;

    struct dirent *entity;
    DIR *dir = opendir(dirPath);

    if (dir != NULL) 
    {
        
        while ((entity = readdir(dir)) != NULL)
        {
            
            if ((strcmp(entity->d_name, ".") != 0) && (strcmp(entity->d_name, "..") != 0)) fileCounter++;
        }

        
        files.capacity = fileCounter;
        files.paths = (char **)RL_MALLOC(files.capacity*sizeof(char *));
        for (unsigned int i = 0; i < files.capacity; i++) files.paths[i] = (char *)RL_MALLOC(MAX_FILEPATH_LENGTH*sizeof(char));

        closedir(dir);

        
        
        ScanDirectoryFiles(dirPath, &files, NULL);

        
        if (files.count != files.capacity) TRACELOG(LOG_WARNING, "FILEIO: Read files count do not match capacity allocated");
    }
    else TRACELOG(LOG_WARNING, "FILEIO: Failed to open requested directory");  

    return files;
}



FilePathList LoadDirectoryFilesEx(const char *basePath, const char *filter, bool scanSubdirs)
{
    FilePathList files = { 0 };

    files.capacity = MAX_FILEPATH_CAPACITY;
    files.paths = (char **)RL_CALLOC(files.capacity, sizeof(char *));
    for (unsigned int i = 0; i < files.capacity; i++) files.paths[i] = (char *)RL_CALLOC(MAX_FILEPATH_LENGTH, sizeof(char));

    
    if (scanSubdirs) ScanDirectoryFilesRecursively(basePath, &files, filter);
    else ScanDirectoryFiles(basePath, &files, filter);

    return files;
}



void UnloadDirectoryFiles(FilePathList files)
{
    for (unsigned int i = 0; i < files.capacity; i++) RL_FREE(files.paths[i]);

    RL_FREE(files.paths);
}


bool ChangeDirectory(const char *dir)
{
    bool result = CHDIR(dir);

    if (result != 0) TRACELOG(LOG_WARNING, "SYSTEM: Failed to change to directory: %s", dir);

    return (result == 0);
}


bool IsPathFile(const char *path)
{
    struct stat pathStat = { 0 };
    stat(path, &pathStat);

    return S_ISREG(pathStat.st_mode);
}


bool IsFileDropped(void)
{
    if (CORE.Window.dropFileCount > 0) return true;
    else return false;
}


FilePathList LoadDroppedFiles(void)
{
    FilePathList files = { 0 };

    files.count = CORE.Window.dropFileCount;
    files.paths = CORE.Window.dropFilepaths;

    return files;
}


void UnloadDroppedFiles(FilePathList files)
{
    

    if (files.count > 0)
    {
        for (unsigned int i = 0; i < files.count; i++) RL_FREE(files.paths[i]);

        RL_FREE(files.paths);

        CORE.Window.dropFileCount = 0;
        CORE.Window.dropFilepaths = NULL;
    }
}


long GetFileModTime(const char *fileName)
{
    struct stat result = { 0 };

    if (stat(fileName, &result) == 0)
    {
        time_t mod = result.st_mtime;

        return (long)mod;
    }

    return 0;
}


unsigned char *CompressData(const unsigned char *data, int dataSize, int *compDataSize)
{
    #define COMPRESSION_QUALITY_DEFLATE  8

    unsigned char *compData = NULL;


    
    struct sdefl sdefl = { 0 };
    int bounds = sdefl_bound(dataSize);
    compData = (unsigned char *)RL_CALLOC(bounds, 1);
    *compDataSize = sdeflate(&sdefl, compData, data, dataSize, COMPRESSION_QUALITY_DEFLATE);   

    TRACELOG(LOG_INFO, "SYSTEM: Compress data: Original size: %i -> Comp. size: %i", dataSize, *compDataSize);


    return compData;
}


unsigned char *DecompressData(const unsigned char *compData, int compDataSize, int *dataSize)
{
    unsigned char *data = NULL;


    
    data = (unsigned char *)RL_CALLOC(MAX_DECOMPRESSION_SIZE*1024*1024, 1);
    int length = sinflate(data, MAX_DECOMPRESSION_SIZE*1024*1024, compData, compDataSize);

    
    
    unsigned char *temp = (unsigned char *)RL_REALLOC(data, length);

    if (temp != NULL) data = temp;
    else TRACELOG(LOG_WARNING, "SYSTEM: Failed to re-allocate required decompression memory");

    *dataSize = length;

    TRACELOG(LOG_INFO, "SYSTEM: Decompress data: Comp. size: %i -> Original size: %i", compDataSize, *dataSize);


    return data;
}


char *EncodeDataBase64(const unsigned char *data, int dataSize, int *outputSize)
{
    static const unsigned char base64encodeTable[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };



    static const int modTable[] = { 0, 2, 1 };

    *outputSize = 4*((dataSize + 2)/3);

    char *encodedData = (char *)RL_MALLOC(*outputSize);

    if (encodedData == NULL) return NULL;

    for (int i = 0, j = 0; i < dataSize;)
    {
        unsigned int octetA = (i < dataSize)? (unsigned char)data[i++] : 0;
        unsigned int octetB = (i < dataSize)? (unsigned char)data[i++] : 0;
        unsigned int octetC = (i < dataSize)? (unsigned char)data[i++] : 0;

        unsigned int triple = (octetA << 0x10) + (octetB << 0x08) + octetC;

        encodedData[j++] = base64encodeTable[(triple >> 3*6) & 0x3F];
        encodedData[j++] = base64encodeTable[(triple >> 2*6) & 0x3F];
        encodedData[j++] = base64encodeTable[(triple >> 1*6) & 0x3F];
        encodedData[j++] = base64encodeTable[(triple >> 0*6) & 0x3F];
    }

    for (int i = 0; i < modTable[dataSize%3]; i++) encodedData[*outputSize - 1 - i] = '=';  

    return encodedData;
}


unsigned char *DecodeDataBase64(const unsigned char *data, int *outputSize)
{
    static const unsigned char base64decodeTable[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };




    
    int outSize = 0;
    for (int i = 0; data[4*i] != 0; i++)
    {
        if (data[4*i + 3] == '=')
        {
            if (data[4*i + 2] == '=') outSize += 1;
            else outSize += 2;
        }
        else outSize += 3;
    }

    
    unsigned char *decodedData = (unsigned char *)RL_MALLOC(outSize);

    for (int i = 0; i < outSize/3; i++)
    {
        unsigned char a = base64decodeTable[(int)data[4*i]];
        unsigned char b = base64decodeTable[(int)data[4*i + 1]];
        unsigned char c = base64decodeTable[(int)data[4*i + 2]];
        unsigned char d = base64decodeTable[(int)data[4*i + 3]];

        decodedData[3*i] = (a << 2) | (b >> 4);
        decodedData[3*i + 1] = (b << 4) | (c >> 2);
        decodedData[3*i + 2] = (c << 6) | d;
    }

    if (outSize%3 == 1)
    {
        int n = outSize/3;
        unsigned char a = base64decodeTable[(int)data[4*n]];
        unsigned char b = base64decodeTable[(int)data[4*n + 1]];
        decodedData[outSize - 1] = (a << 2) | (b >> 4);
    }
    else if (outSize%3 == 2)
    {
        int n = outSize/3;
        unsigned char a = base64decodeTable[(int)data[4*n]];
        unsigned char b = base64decodeTable[(int)data[4*n + 1]];
        unsigned char c = base64decodeTable[(int)data[4*n + 2]];
        decodedData[outSize - 2] = (a << 2) | (b >> 4);
        decodedData[outSize - 1] = (b << 4) | (c >> 2);
    }

    *outputSize = outSize;
    return decodedData;
}






void OpenURL(const char *url)
{
    
    
    if (strchr(url, '\'') != NULL)
    {
        TRACELOG(LOG_WARNING, "SYSTEM: Provided URL is not valid");
    }
    else {

        char *cmd = (char *)RL_CALLOC(strlen(url) + 32, sizeof(char));
    #if defined(_WIN32)
        sprintf(cmd, "explorer \"%s\"", url);
    #endif
    #if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        sprintf(cmd, "xdg-open '%s'", url); 
    #endif
    #if defined(__APPLE__)
        sprintf(cmd, "open '%s'", url);
    #endif
        int result = system(cmd);
        if (result == -1) TRACELOG(LOG_WARNING, "OpenURL() child process could not be created");
        RL_FREE(cmd);


        emscripten_run_script(TextFormat("window.open('%s', '_blank')", url));


        JNIEnv *env = NULL;
        JavaVM *vm = CORE.Android.app->activity->vm;
        (*vm)->AttachCurrentThread(vm, &env, NULL);

        jstring urlString = (*env)->NewStringUTF(env, url);
        jclass uriClass = (*env)->FindClass(env, "android/net/Uri");
        jmethodID uriParse = (*env)->GetStaticMethodID(env, uriClass, "parse", "(Ljava/lang/String;)Landroid/net/Uri;");
        jobject uri = (*env)->CallStaticObjectMethod(env, uriClass, uriParse, urlString);

        jclass intentClass = (*env)->FindClass(env, "android/content/Intent");
        jfieldID actionViewId = (*env)->GetStaticFieldID(env, intentClass, "ACTION_VIEW", "Ljava/lang/String;");
        jobject actionView = (*env)->GetStaticObjectField(env, intentClass, actionViewId);
        jmethodID newIntent = (*env)->GetMethodID(env, intentClass, "<init>", "(Ljava/lang/String;Landroid/net/Uri;)V");
        jobject intent = (*env)->AllocObject(env, intentClass);

        (*env)->CallVoidMethod(env, intent, newIntent, actionView, uri);
        jclass activityClass = (*env)->FindClass(env, "android/app/Activity");
        jmethodID startActivity = (*env)->GetMethodID(env, activityClass, "startActivity", "(Landroid/content/Intent;)V");
        (*env)->CallVoidMethod(env, CORE.Android.app->activity->clazz, startActivity, intent);

        (*vm)->DetachCurrentThread(vm);

    }
}





bool IsKeyPressed(int key)
{
    bool pressed = false;

    if ((CORE.Input.Keyboard.previousKeyState[key] == 0) && (CORE.Input.Keyboard.currentKeyState[key] == 1)) pressed = true;

    return pressed;
}


bool IsKeyDown(int key)
{
    if (CORE.Input.Keyboard.currentKeyState[key] == 1) return true;
    else return false;
}


bool IsKeyReleased(int key)
{
    bool released = false;

    if ((CORE.Input.Keyboard.previousKeyState[key] == 1) && (CORE.Input.Keyboard.currentKeyState[key] == 0)) released = true;

    return released;
}


bool IsKeyUp(int key)
{
    if (CORE.Input.Keyboard.currentKeyState[key] == 0) return true;
    else return false;
}


int GetKeyPressed(void)
{
    int value = 0;

    if (CORE.Input.Keyboard.keyPressedQueueCount > 0)
    {
        
        value = CORE.Input.Keyboard.keyPressedQueue[0];

        
        for (int i = 0; i < (CORE.Input.Keyboard.keyPressedQueueCount - 1); i++)
            CORE.Input.Keyboard.keyPressedQueue[i] = CORE.Input.Keyboard.keyPressedQueue[i + 1];

        
        CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount - 1] = 0;
        CORE.Input.Keyboard.keyPressedQueueCount--;
    }

    return value;
}


int GetCharPressed(void)
{
    int value = 0;

    if (CORE.Input.Keyboard.charPressedQueueCount > 0)
    {
        
        value = CORE.Input.Keyboard.charPressedQueue[0];

        
        for (int i = 0; i < (CORE.Input.Keyboard.charPressedQueueCount - 1); i++)
            CORE.Input.Keyboard.charPressedQueue[i] = CORE.Input.Keyboard.charPressedQueue[i + 1];

        
        CORE.Input.Keyboard.charPressedQueue[CORE.Input.Keyboard.charPressedQueueCount - 1] = 0;
        CORE.Input.Keyboard.charPressedQueueCount--;
    }

    return value;
}



void SetExitKey(int key)
{

    CORE.Input.Keyboard.exitKey = key;

}




bool IsGamepadAvailable(int gamepad)
{
    bool result = false;

    if ((gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad]) result = true;

    return result;
}


const char *GetGamepadName(int gamepad)
{

    if (CORE.Input.Gamepad.ready[gamepad]) return glfwGetJoystickName(gamepad);
    else return NULL;


    if (CORE.Input.Gamepad.ready[gamepad]) ioctl(CORE.Input.Gamepad.streamId[gamepad], JSIOCGNAME(64), &CORE.Input.Gamepad.name[gamepad]);
    return CORE.Input.Gamepad.name[gamepad];


    return CORE.Input.Gamepad.name[gamepad];

    return NULL;
}


int GetGamepadAxisCount(int gamepad)
{

    int axisCount = 0;
    if (CORE.Input.Gamepad.ready[gamepad]) ioctl(CORE.Input.Gamepad.streamId[gamepad], JSIOCGAXES, &axisCount);
    CORE.Input.Gamepad.axisCount = axisCount;


    return CORE.Input.Gamepad.axisCount;
}


float GetGamepadAxisMovement(int gamepad, int axis)
{
    float value = 0;

    if ((gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad] && (axis < MAX_GAMEPAD_AXIS) && (fabsf(CORE.Input.Gamepad.axisState[gamepad][axis]) > 0.1f)) value = CORE.Input.Gamepad.axisState[gamepad][axis];

    return value;
}


bool IsGamepadButtonPressed(int gamepad, int button)
{
    bool pressed = false;

    if ((gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad] && (button < MAX_GAMEPAD_BUTTONS) && (CORE.Input.Gamepad.previousButtonState[gamepad][button] == 0) && (CORE.Input.Gamepad.currentButtonState[gamepad][button] == 1)) pressed = true;

    return pressed;
}


bool IsGamepadButtonDown(int gamepad, int button)
{
    bool result = false;

    if ((gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad] && (button < MAX_GAMEPAD_BUTTONS) && (CORE.Input.Gamepad.currentButtonState[gamepad][button] == 1)) result = true;

    return result;
}


bool IsGamepadButtonReleased(int gamepad, int button)
{
    bool released = false;

    if ((gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad] && (button < MAX_GAMEPAD_BUTTONS) && (CORE.Input.Gamepad.previousButtonState[gamepad][button] == 1) && (CORE.Input.Gamepad.currentButtonState[gamepad][button] == 0)) released = true;

    return released;
}


bool IsGamepadButtonUp(int gamepad, int button)
{
    bool result = false;

    if ((gamepad < MAX_GAMEPADS) && CORE.Input.Gamepad.ready[gamepad] && (button < MAX_GAMEPAD_BUTTONS) && (CORE.Input.Gamepad.currentButtonState[gamepad][button] == 0)) result = true;

    return result;
}


int GetGamepadButtonPressed(void)
{
    return CORE.Input.Gamepad.lastButtonPressed;
}


int SetGamepadMappings(const char *mappings)
{
    int result = 0;


    result = glfwUpdateGamepadMappings(mappings);


    return result;
}


bool IsMouseButtonPressed(int button)
{
    bool pressed = false;

    if ((CORE.Input.Mouse.currentButtonState[button] == 1) && (CORE.Input.Mouse.previousButtonState[button] == 0)) pressed = true;

    
    if ((CORE.Input.Touch.currentTouchState[button] == 1) && (CORE.Input.Touch.previousTouchState[button] == 0)) pressed = true;

    return pressed;
}


bool IsMouseButtonDown(int button)
{
    bool down = false;

    if (CORE.Input.Mouse.currentButtonState[button] == 1) down = true;

    
    if (CORE.Input.Touch.currentTouchState[button] == 1) down = true;

    return down;
}


bool IsMouseButtonReleased(int button)
{
    bool released = false;

    if ((CORE.Input.Mouse.currentButtonState[button] == 0) && (CORE.Input.Mouse.previousButtonState[button] == 1)) released = true;

    
    if ((CORE.Input.Touch.currentTouchState[button] == 0) && (CORE.Input.Touch.previousTouchState[button] == 1)) released = true;

    return released;
}


bool IsMouseButtonUp(int button)
{
    return !IsMouseButtonDown(button);
}


int GetMouseX(void)
{

    return (int)CORE.Input.Touch.position[0].x;

    return (int)((CORE.Input.Mouse.currentPosition.x + CORE.Input.Mouse.offset.x)*CORE.Input.Mouse.scale.x);

}


int GetMouseY(void)
{

    return (int)CORE.Input.Touch.position[0].y;

    return (int)((CORE.Input.Mouse.currentPosition.y + CORE.Input.Mouse.offset.y)*CORE.Input.Mouse.scale.y);

}


Vector2 GetMousePosition(void)
{
    Vector2 position = { 0 };


    position = GetTouchPosition(0);

    position.x = (CORE.Input.Mouse.currentPosition.x + CORE.Input.Mouse.offset.x)*CORE.Input.Mouse.scale.x;
    position.y = (CORE.Input.Mouse.currentPosition.y + CORE.Input.Mouse.offset.y)*CORE.Input.Mouse.scale.y;


    return position;
}


Vector2 GetMouseDelta(void)
{
    Vector2 delta = { 0 };

    delta.x = CORE.Input.Mouse.currentPosition.x - CORE.Input.Mouse.previousPosition.x;
    delta.y = CORE.Input.Mouse.currentPosition.y - CORE.Input.Mouse.previousPosition.y;

    return delta;
}


void SetMousePosition(int x, int y)
{
    CORE.Input.Mouse.currentPosition = (Vector2){ (float)x, (float)y };
    CORE.Input.Mouse.previousPosition = CORE.Input.Mouse.currentPosition;


    
    glfwSetCursorPos(CORE.Window.handle, CORE.Input.Mouse.currentPosition.x, CORE.Input.Mouse.currentPosition.y);

}



void SetMouseOffset(int offsetX, int offsetY)
{
    CORE.Input.Mouse.offset = (Vector2){ (float)offsetX, (float)offsetY };
}



void SetMouseScale(float scaleX, float scaleY)
{
    CORE.Input.Mouse.scale = (Vector2){ scaleX, scaleY };
}


float GetMouseWheelMove(void)
{
    float result = 0.0f;


    if (fabsf(CORE.Input.Mouse.currentWheelMove.x) > fabsf(CORE.Input.Mouse.currentWheelMove.y)) result = (float)CORE.Input.Mouse.currentWheelMove.x;
    else result = (float)CORE.Input.Mouse.currentWheelMove.y;


    return result;
}


Vector2 GetMouseWheelMoveV(void)
{
    Vector2 result = { 0 };

    result = CORE.Input.Mouse.currentWheelMove;

    return result;
}



void SetMouseCursor(int cursor)
{

    CORE.Input.Mouse.cursor = cursor;
    if (cursor == MOUSE_CURSOR_DEFAULT) glfwSetCursor(CORE.Window.handle, NULL);
    else {
        
        glfwSetCursor(CORE.Window.handle, glfwCreateStandardCursor(0x00036000 + cursor));
    }

}


int GetTouchX(void)
{

    return (int)CORE.Input.Touch.position[0].x;

    return GetMouseX();

}


int GetTouchY(void)
{

    return (int)CORE.Input.Touch.position[0].y;

    return GetMouseY();

}



Vector2 GetTouchPosition(int index)
{
    Vector2 position = { -1.0f, -1.0f };


    
    
    
    if (index == 0) position = GetMousePosition();


    if (index < MAX_TOUCH_POINTS) position = CORE.Input.Touch.position[index];
    else TRACELOG(LOG_WARNING, "INPUT: Required touch point out of range (Max touch points: %i)", MAX_TOUCH_POINTS);


    return position;
}


int GetTouchPointId(int index)
{
    int id = -1;

    if (index < MAX_TOUCH_POINTS) id = CORE.Input.Touch.pointId[index];

    return id;
}


int GetTouchPointCount(void)
{
    return CORE.Input.Touch.pointCount;
}









static bool InitGraphicsDevice(int width, int height)
{
    CORE.Window.screen.width = width;            
    CORE.Window.screen.height = height;          
    CORE.Window.screenScale = MatrixIdentity();  

    
    


    glfwSetErrorCallback(ErrorCallback);


    glfwInitHint(GLFW_COCOA_CHDIR_RESOURCES, GLFW_FALSE);


    if (!glfwInit())
    {
        TRACELOG(LOG_WARNING, "GLFW: Failed to initialize GLFW");
        return false;
    }

    glfwDefaultWindowHints();                       
    
    
    
    
    
    
    
    

    
    if ((CORE.Window.flags & FLAG_FULLSCREEN_MODE) > 0) CORE.Window.fullscreen = true;

    if ((CORE.Window.flags & FLAG_WINDOW_HIDDEN) > 0) glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE); 
    else glfwWindowHint(GLFW_VISIBLE, GLFW_TRUE);     

    if ((CORE.Window.flags & FLAG_WINDOW_UNDECORATED) > 0) glfwWindowHint(GLFW_DECORATED, GLFW_FALSE); 
    else glfwWindowHint(GLFW_DECORATED, GLFW_TRUE);   

    if ((CORE.Window.flags & FLAG_WINDOW_RESIZABLE) > 0) glfwWindowHint(GLFW_RESIZABLE, GLFW_TRUE); 
    else glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);  

    
    if ((CORE.Window.flags & FLAG_WINDOW_MINIMIZED) > 0) CORE.Window.flags &= ~FLAG_WINDOW_MINIMIZED;

    
    if ((CORE.Window.flags & FLAG_WINDOW_MAXIMIZED) > 0) CORE.Window.flags &= ~FLAG_WINDOW_MAXIMIZED;

    if ((CORE.Window.flags & FLAG_WINDOW_UNFOCUSED) > 0) glfwWindowHint(GLFW_FOCUSED, GLFW_FALSE);
    else glfwWindowHint(GLFW_FOCUSED, GLFW_TRUE);

    if ((CORE.Window.flags & FLAG_WINDOW_TOPMOST) > 0) glfwWindowHint(GLFW_FLOATING, GLFW_TRUE);
    else glfwWindowHint(GLFW_FLOATING, GLFW_FALSE);

    

    if ((CORE.Window.flags & FLAG_WINDOW_TRANSPARENT) > 0) glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);     
    else glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_FALSE);  

    if ((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) > 0)
    {
        
        
        
        glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);   
    #if defined(__APPLE__)
        glfwWindowHint(GLFW_COCOA_RETINA_FRAMEBUFFER, GLFW_TRUE);
    #endif
    }
    else glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_FALSE);

    
    if ((CORE.Window.flags & FLAG_WINDOW_MOUSE_PASSTHROUGH) > 0) glfwWindowHint(GLFW_MOUSE_PASSTHROUGH, GLFW_TRUE);
    else glfwWindowHint(GLFW_MOUSE_PASSTHROUGH, GLFW_FALSE);


    if (CORE.Window.flags & FLAG_MSAA_4X_HINT)
    {
        
        TRACELOG(LOG_INFO, "DISPLAY: Trying to enable MSAA x4");
        glfwWindowHint(GLFW_SAMPLES, 4);   
    }

    
    
    

    
    if (rlGetVersion() == RL_OPENGL_21)
    {
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);          
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);          
    }
    else if (rlGetVersion() == RL_OPENGL_33)
    {
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);          
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);          
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); 
                                                                       

        glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);  

        glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_FALSE); 

        
    }
    else if (rlGetVersion() == RL_OPENGL_43)
    {
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);          
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);          
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
        glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_FALSE);

        glfwWindowHint(GLFW_OPENGL_DEBUG_CONTEXT, GLFW_TRUE);   

    }
    else if (rlGetVersion() == RL_OPENGL_ES_20)                 
    {
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
        glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);

        glfwWindowHint(GLFW_CONTEXT_CREATION_API, GLFW_EGL_CONTEXT_API);

        glfwWindowHint(GLFW_CONTEXT_CREATION_API, GLFW_NATIVE_CONTEXT_API);

    }


    
    
    
    
    if (MAX_GAMEPADS > 0) glfwSetJoystickCallback(NULL);



    
    GLFWmonitor *monitor = glfwGetPrimaryMonitor();
    if (!monitor)
    {
        TRACELOG(LOG_WARNING, "GLFW: Failed to get primary monitor");
        return false;
    }

    const GLFWvidmode *mode = glfwGetVideoMode(monitor);

    CORE.Window.display.width = mode->width;
    CORE.Window.display.height = mode->height;

    
    if (CORE.Window.screen.width == 0) CORE.Window.screen.width = CORE.Window.display.width;
    if (CORE.Window.screen.height == 0) CORE.Window.screen.height = CORE.Window.display.height;



    
    CORE.Window.display.width = CORE.Window.screen.width;
    CORE.Window.display.height = CORE.Window.screen.height;


    if (CORE.Window.fullscreen)
    {
        
        if ((CORE.Window.screen.height == CORE.Window.display.height) && (CORE.Window.screen.width == CORE.Window.display.width))
        {
            
            
            CORE.Window.position.x = CORE.Window.display.width/4;
            CORE.Window.position.y = CORE.Window.display.height/4;
        }
        else {
            CORE.Window.position.x = CORE.Window.display.width/2 - CORE.Window.screen.width/2;
            CORE.Window.position.y = CORE.Window.display.height/2 - CORE.Window.screen.height/2;
        }

        if (CORE.Window.position.x < 0) CORE.Window.position.x = 0;
        if (CORE.Window.position.y < 0) CORE.Window.position.y = 0;

        
        int count = 0;
        const GLFWvidmode *modes = glfwGetVideoModes(glfwGetPrimaryMonitor(), &count);

        
        for (int i = 0; i < count; i++)
        {
            if ((unsigned int)modes[i].width >= CORE.Window.screen.width)
            {
                if ((unsigned int)modes[i].height >= CORE.Window.screen.height)
                {
                    CORE.Window.display.width = modes[i].width;
                    CORE.Window.display.height = modes[i].height;
                    break;
                }
            }
        }
        TRACELOG(LOG_WARNING, "SYSTEM: Closest fullscreen videomode: %i x %i", CORE.Window.display.width, CORE.Window.display.height);

        
        
        
        

        
        
        
        
        
        SetupFramebuffer(CORE.Window.display.width, CORE.Window.display.height);

        CORE.Window.handle = glfwCreateWindow(CORE.Window.display.width, CORE.Window.display.height, (CORE.Window.title != 0)? CORE.Window.title : " ", glfwGetPrimaryMonitor(), NULL);

        
        
    }
    else {

        
        if ((CORE.Window.screen.height == CORE.Window.display.height) && (CORE.Window.screen.width == CORE.Window.display.width))
        {
            glfwWindowHint(GLFW_AUTO_ICONIFY, 0);
        }

        
        CORE.Window.handle = glfwCreateWindow(CORE.Window.screen.width, CORE.Window.screen.height, (CORE.Window.title != 0)? CORE.Window.title : " ", NULL, NULL);

        if (CORE.Window.handle)
        {
            CORE.Window.render.width = CORE.Window.screen.width;
            CORE.Window.render.height = CORE.Window.screen.height;
        }
    }

    if (!CORE.Window.handle)
    {
        glfwTerminate();
        TRACELOG(LOG_WARNING, "GLFW: Failed to initialize Window");
        return false;
    }

    
    glfwSetWindowSizeCallback(CORE.Window.handle, WindowSizeCallback);      

    glfwSetWindowMaximizeCallback(CORE.Window.handle, WindowMaximizeCallback);

    glfwSetWindowIconifyCallback(CORE.Window.handle, WindowIconifyCallback);
    glfwSetWindowFocusCallback(CORE.Window.handle, WindowFocusCallback);
    glfwSetDropCallback(CORE.Window.handle, WindowDropCallback);

    
    glfwSetKeyCallback(CORE.Window.handle, KeyCallback);
    glfwSetCharCallback(CORE.Window.handle, CharCallback);
    glfwSetMouseButtonCallback(CORE.Window.handle, MouseButtonCallback);
    glfwSetCursorPosCallback(CORE.Window.handle, MouseCursorPosCallback);   
    glfwSetScrollCallback(CORE.Window.handle, MouseScrollCallback);
    glfwSetCursorEnterCallback(CORE.Window.handle, CursorEnterCallback);

    glfwMakeContextCurrent(CORE.Window.handle);


    glfwSetInputMode(CORE.Window.handle, GLFW_LOCK_KEY_MODS, GLFW_TRUE);    

    glfwSwapInterval(0);        


    
    
    if (CORE.Window.flags & FLAG_VSYNC_HINT)
    {
        
        glfwSwapInterval(1);
        TRACELOG(LOG_INFO, "DISPLAY: Trying to enable VSYNC");
    }

    int fbWidth = CORE.Window.screen.width;
    int fbHeight = CORE.Window.screen.height;


    if ((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) > 0)
    {
        
        
    #if !defined(__APPLE__)
        glfwGetFramebufferSize(CORE.Window.handle, &fbWidth, &fbHeight);

        
        CORE.Window.screenScale = MatrixScale((float)fbWidth/CORE.Window.screen.width, (float)fbHeight/CORE.Window.screen.height, 1.0f);

        
        SetMouseScale((float)CORE.Window.screen.width/fbWidth, (float)CORE.Window.screen.height/fbHeight);
    #endif
    }


    CORE.Window.render.width = fbWidth;
    CORE.Window.render.height = fbHeight;
    CORE.Window.currentFbo.width = fbWidth;
    CORE.Window.currentFbo.height = fbHeight;

    TRACELOG(LOG_INFO, "DISPLAY: Device initialized successfully");
    TRACELOG(LOG_INFO, "    > Display size: %i x %i", CORE.Window.display.width, CORE.Window.display.height);
    TRACELOG(LOG_INFO, "    > Screen size:  %i x %i", CORE.Window.screen.width, CORE.Window.screen.height);
    TRACELOG(LOG_INFO, "    > Render size:  %i x %i", CORE.Window.render.width, CORE.Window.render.height);
    TRACELOG(LOG_INFO, "    > Viewport offsets: %i, %i", CORE.Window.renderOffset.x, CORE.Window.renderOffset.y);




    CORE.Window.fullscreen = true;
    CORE.Window.flags |= FLAG_FULLSCREEN_MODE;


    bcm_host_init();

    DISPMANX_ELEMENT_HANDLE_T dispmanElement = { 0 };
    DISPMANX_DISPLAY_HANDLE_T dispmanDisplay = { 0 };
    DISPMANX_UPDATE_HANDLE_T dispmanUpdate = { 0 };

    VC_RECT_T dstRect = { 0 };
    VC_RECT_T srcRect = { 0 };



    CORE.Window.fd = -1;
    CORE.Window.connector = NULL;
    CORE.Window.modeIndex = -1;
    CORE.Window.crtc = NULL;
    CORE.Window.gbmDevice = NULL;
    CORE.Window.gbmSurface = NULL;
    CORE.Window.prevBO = NULL;
    CORE.Window.prevFB = 0;


    CORE.Window.fd = open(DEFAULT_GRAPHIC_DEVICE_DRM, O_RDWR);

    TRACELOG(LOG_INFO, "DISPLAY: No graphic card set, trying platform-gpu-card");
    CORE.Window.fd = open("/dev/dri/by-path/platform-gpu-card",  O_RDWR); 

    if ((-1 == CORE.Window.fd) || (drmModeGetResources(CORE.Window.fd) == NULL))
    {
        TRACELOG(LOG_INFO, "DISPLAY: Failed to open platform-gpu-card, trying card1");
        CORE.Window.fd = open("/dev/dri/card1", O_RDWR); 
    }

    if ((-1 == CORE.Window.fd) || (drmModeGetResources(CORE.Window.fd) == NULL))
    {
        TRACELOG(LOG_INFO, "DISPLAY: Failed to open graphic card1, trying card0");
        CORE.Window.fd = open("/dev/dri/card0", O_RDWR); 
    }

    if (-1 == CORE.Window.fd)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to open graphic card");
        return false;
    }

    drmModeRes *res = drmModeGetResources(CORE.Window.fd);
    if (!res)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed get DRM resources");
        return false;
    }

    TRACELOG(LOG_TRACE, "DISPLAY: Connectors found: %i", res->count_connectors);
    for (size_t i = 0; i < res->count_connectors; i++)
    {
        TRACELOG(LOG_TRACE, "DISPLAY: Connector index %i", i);
        drmModeConnector *con = drmModeGetConnector(CORE.Window.fd, res->connectors[i]);
        TRACELOG(LOG_TRACE, "DISPLAY: Connector modes detected: %i", con->count_modes);
        if ((con->connection == DRM_MODE_CONNECTED) && (con->encoder_id))
        {
            TRACELOG(LOG_TRACE, "DISPLAY: DRM mode connected");
            CORE.Window.connector = con;
            break;
        }
        else {
            TRACELOG(LOG_TRACE, "DISPLAY: DRM mode NOT connected (deleting)");
            drmModeFreeConnector(con);
        }
    }

    if (!CORE.Window.connector)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: No suitable DRM connector found");
        drmModeFreeResources(res);
        return false;
    }

    drmModeEncoder *enc = drmModeGetEncoder(CORE.Window.fd, CORE.Window.connector->encoder_id);
    if (!enc)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to get DRM mode encoder");
        drmModeFreeResources(res);
        return false;
    }

    CORE.Window.crtc = drmModeGetCrtc(CORE.Window.fd, enc->crtc_id);
    if (!CORE.Window.crtc)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to get DRM mode crtc");
        drmModeFreeEncoder(enc);
        drmModeFreeResources(res);
        return false;
    }

    
    if ((CORE.Window.screen.width <= 0) || (CORE.Window.screen.height <= 0))
    {
        TRACELOG(LOG_TRACE, "DISPLAY: Selecting DRM connector mode for current used mode...");

        CORE.Window.modeIndex = FindMatchingConnectorMode(CORE.Window.connector, &CORE.Window.crtc->mode);

        if (CORE.Window.modeIndex < 0)
        {
            TRACELOG(LOG_WARNING, "DISPLAY: No matching DRM connector mode found");
            drmModeFreeEncoder(enc);
            drmModeFreeResources(res);
            return false;
        }

        CORE.Window.screen.width = CORE.Window.display.width;
        CORE.Window.screen.height = CORE.Window.display.height;
    }

    const bool allowInterlaced = CORE.Window.flags & FLAG_INTERLACED_HINT;
    const int fps = (CORE.Time.target > 0) ? (1.0/CORE.Time.target) : 60;

    
    CORE.Window.modeIndex = FindExactConnectorMode(CORE.Window.connector, CORE.Window.screen.width, CORE.Window.screen.height, fps, allowInterlaced);

    
    if (CORE.Window.modeIndex < 0) CORE.Window.modeIndex = FindNearestConnectorMode(CORE.Window.connector, CORE.Window.screen.width, CORE.Window.screen.height, fps, allowInterlaced);

    
    if (CORE.Window.modeIndex < 0) CORE.Window.modeIndex = FindExactConnectorMode(CORE.Window.connector, CORE.Window.screen.width, CORE.Window.screen.height, fps, true);

    
    if (CORE.Window.modeIndex < 0) CORE.Window.modeIndex = FindNearestConnectorMode(CORE.Window.connector, CORE.Window.screen.width, CORE.Window.screen.height, fps, true);

    
    if (CORE.Window.modeIndex < 0)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to find a suitable DRM connector mode");
        drmModeFreeEncoder(enc);
        drmModeFreeResources(res);
        return false;
    }

    CORE.Window.display.width = CORE.Window.connector->modes[CORE.Window.modeIndex].hdisplay;
    CORE.Window.display.height = CORE.Window.connector->modes[CORE.Window.modeIndex].vdisplay;

    TRACELOG(LOG_INFO, "DISPLAY: Selected DRM connector mode %s (%ux%u%c@%u)", CORE.Window.connector->modes[CORE.Window.modeIndex].name, CORE.Window.connector->modes[CORE.Window.modeIndex].hdisplay, CORE.Window.connector->modes[CORE.Window.modeIndex].vdisplay, (CORE.Window.connector->modes[CORE.Window.modeIndex].flags & DRM_MODE_FLAG_INTERLACE) ? 'i' : 'p', CORE.Window.connector->modes[CORE.Window.modeIndex].vrefresh);



    
    CORE.Window.render.width = CORE.Window.screen.width;
    CORE.Window.render.height = CORE.Window.screen.height;

    drmModeFreeEncoder(enc);
    enc = NULL;

    drmModeFreeResources(res);
    res = NULL;

    CORE.Window.gbmDevice = gbm_create_device(CORE.Window.fd);
    if (!CORE.Window.gbmDevice)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to create GBM device");
        return false;
    }

    CORE.Window.gbmSurface = gbm_surface_create(CORE.Window.gbmDevice, CORE.Window.connector->modes[CORE.Window.modeIndex].hdisplay, CORE.Window.connector->modes[CORE.Window.modeIndex].vdisplay, GBM_FORMAT_ARGB8888, GBM_BO_USE_SCANOUT | GBM_BO_USE_RENDERING);
    if (!CORE.Window.gbmSurface)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to create GBM surface");
        return false;
    }


    EGLint samples = 0;
    EGLint sampleBuffer = 0;
    if (CORE.Window.flags & FLAG_MSAA_4X_HINT)
    {
        samples = 4;
        sampleBuffer = 1;
        TRACELOG(LOG_INFO, "DISPLAY: Trying to enable MSAA x4");
    }

    const EGLint framebufferAttribs[] = {
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,       EGL_SURFACE_TYPE, EGL_WINDOW_BIT,  EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8,  EGL_ALPHA_SIZE, 8,   EGL_DEPTH_SIZE, 16,  EGL_SAMPLE_BUFFERS, sampleBuffer, EGL_SAMPLES, samples, EGL_NONE };
















    const EGLint contextAttribs[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };



    EGLint numConfigs = 0;

    

    CORE.Window.device = eglGetDisplay((EGLNativeDisplayType)CORE.Window.gbmDevice);

    CORE.Window.device = eglGetDisplay(EGL_DEFAULT_DISPLAY);

    if (CORE.Window.device == EGL_NO_DISPLAY)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to initialize EGL device");
        return false;
    }

    
    if (eglInitialize(CORE.Window.device, NULL, NULL) == EGL_FALSE)
    {
        
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to initialize EGL device");
        return false;
    }


    if (!eglChooseConfig(CORE.Window.device, NULL, NULL, 0, &numConfigs))
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to get EGL config count: 0x%x", eglGetError());
        return false;
    }

    TRACELOG(LOG_TRACE, "DISPLAY: EGL configs available: %d", numConfigs);

    EGLConfig *configs = RL_CALLOC(numConfigs, sizeof(*configs));
    if (!configs)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to get memory for EGL configs");
        return false;
    }

    EGLint matchingNumConfigs = 0;
    if (!eglChooseConfig(CORE.Window.device, framebufferAttribs, configs, numConfigs, &matchingNumConfigs))
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to choose EGL config: 0x%x", eglGetError());
        free(configs);
        return false;
    }

    TRACELOG(LOG_TRACE, "DISPLAY: EGL matching configs available: %d", matchingNumConfigs);

    
    int found = 0;
    for (EGLint i = 0; i < matchingNumConfigs; ++i)
    {
        EGLint id = 0;
        if (!eglGetConfigAttrib(CORE.Window.device, configs[i], EGL_NATIVE_VISUAL_ID, &id))
        {
            TRACELOG(LOG_WARNING, "DISPLAY: Failed to get EGL config attribute: 0x%x", eglGetError());
            continue;
        }

        if (GBM_FORMAT_ARGB8888 == id)
        {
            TRACELOG(LOG_TRACE, "DISPLAY: Using EGL config: %d", i);
            CORE.Window.config = configs[i];
            found = 1;
            break;
        }
    }

    RL_FREE(configs);

    if (!found)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to find a suitable EGL config");
        return false;
    }

    
    eglChooseConfig(CORE.Window.device, framebufferAttribs, &CORE.Window.config, 1, &numConfigs);


    
    eglBindAPI(EGL_OPENGL_ES_API);

    
    CORE.Window.context = eglCreateContext(CORE.Window.device, CORE.Window.config, EGL_NO_CONTEXT, contextAttribs);
    if (CORE.Window.context == EGL_NO_CONTEXT)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to create EGL context");
        return false;
    }


    
    

    EGLint displayFormat = 0;

    
    
    eglGetConfigAttrib(CORE.Window.device, CORE.Window.config, EGL_NATIVE_VISUAL_ID, &displayFormat);

    
    
    
    
    
    SetupFramebuffer(CORE.Window.display.width, CORE.Window.display.height);

    ANativeWindow_setBuffersGeometry(CORE.Android.app->window, CORE.Window.render.width, CORE.Window.render.height, displayFormat);
    

    CORE.Window.surface = eglCreateWindowSurface(CORE.Window.device, CORE.Window.config, CORE.Android.app->window, NULL);



    graphics_get_display_size(0, &CORE.Window.display.width, &CORE.Window.display.height);

    
    if (CORE.Window.screen.width <= 0) CORE.Window.screen.width = CORE.Window.display.width;
    if (CORE.Window.screen.height <= 0) CORE.Window.screen.height = CORE.Window.display.height;

    
    
    
    
    
    SetupFramebuffer(CORE.Window.display.width, CORE.Window.display.height);

    dstRect.x = 0;
    dstRect.y = 0;
    dstRect.width = CORE.Window.display.width;
    dstRect.height = CORE.Window.display.height;

    srcRect.x = 0;
    srcRect.y = 0;
    srcRect.width = CORE.Window.render.width << 16;
    srcRect.height = CORE.Window.render.height << 16;

    
    

    VC_DISPMANX_ALPHA_T alpha = { 0 };
    alpha.flags = DISPMANX_FLAGS_ALPHA_FIXED_ALL_PIXELS;
    
    alpha.opacity = 255;    
    alpha.mask = 0;

    dispmanDisplay = vc_dispmanx_display_open(0);   
    dispmanUpdate = vc_dispmanx_update_start(0);

    dispmanElement = vc_dispmanx_element_add(dispmanUpdate, dispmanDisplay, 0, &dstRect, 0, &srcRect, DISPMANX_PROTECTION_NONE, &alpha, 0, DISPMANX_NO_ROTATE);

    CORE.Window.handle.element = dispmanElement;
    CORE.Window.handle.width = CORE.Window.render.width;
    CORE.Window.handle.height = CORE.Window.render.height;
    vc_dispmanx_update_submit_sync(dispmanUpdate);

    CORE.Window.surface = eglCreateWindowSurface(CORE.Window.device, CORE.Window.config, &CORE.Window.handle, NULL);

    const unsigned char *const renderer = glGetString(GL_RENDERER);
    if (renderer) TRACELOG(LOG_INFO, "DISPLAY: Renderer name is: %s", renderer);
    else TRACELOG(LOG_WARNING, "DISPLAY: Failed to get renderer name");
    



    CORE.Window.surface = eglCreateWindowSurface(CORE.Window.device, CORE.Window.config, (EGLNativeWindowType)CORE.Window.gbmSurface, NULL);
    if (EGL_NO_SURFACE == CORE.Window.surface)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to create EGL window surface: 0x%04x", eglGetError());
        return false;
    }

    
    
    
    
    
    SetupFramebuffer(CORE.Window.display.width, CORE.Window.display.height);


    
    

    if (eglMakeCurrent(CORE.Window.device, CORE.Window.surface, CORE.Window.surface, CORE.Window.context) == EGL_FALSE)
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Failed to attach EGL rendering context to EGL surface");
        return false;
    }
    else {
        CORE.Window.render.width = CORE.Window.screen.width;
        CORE.Window.render.height = CORE.Window.screen.height;
        CORE.Window.currentFbo.width = CORE.Window.render.width;
        CORE.Window.currentFbo.height = CORE.Window.render.height;

        TRACELOG(LOG_INFO, "DISPLAY: Device initialized successfully");
        TRACELOG(LOG_INFO, "    > Display size: %i x %i", CORE.Window.display.width, CORE.Window.display.height);
        TRACELOG(LOG_INFO, "    > Screen size:  %i x %i", CORE.Window.screen.width, CORE.Window.screen.height);
        TRACELOG(LOG_INFO, "    > Render size:  %i x %i", CORE.Window.render.width, CORE.Window.render.height);
        TRACELOG(LOG_INFO, "    > Viewport offsets: %i, %i", CORE.Window.renderOffset.x, CORE.Window.renderOffset.y);
    }


    
    

    rlLoadExtensions(glfwGetProcAddress);

    rlLoadExtensions(eglGetProcAddress);


    
    
    rlglInit(CORE.Window.currentFbo.width, CORE.Window.currentFbo.height);

    
    
    SetupViewport(CORE.Window.currentFbo.width, CORE.Window.currentFbo.height);


    CORE.Window.ready = true;


    if ((CORE.Window.flags & FLAG_WINDOW_MINIMIZED) > 0) MinimizeWindow();

    return true;
}


static void SetupViewport(int width, int height)
{
    CORE.Window.render.width = width;
    CORE.Window.render.height = height;

    
    
    

    float xScale = 1.0f, yScale = 1.0f;
    glfwGetWindowContentScale(CORE.Window.handle, &xScale, &yScale);
    rlViewport(CORE.Window.renderOffset.x/2*xScale, CORE.Window.renderOffset.y/2*yScale, (CORE.Window.render.width)*xScale, (CORE.Window.render.height)*yScale);

    rlViewport(CORE.Window.renderOffset.x/2, CORE.Window.renderOffset.y/2, CORE.Window.render.width, CORE.Window.render.height);


    rlMatrixMode(RL_PROJECTION);        
    rlLoadIdentity();                   

    
    
    rlOrtho(0, CORE.Window.render.width, CORE.Window.render.height, 0, 0.0f, 1.0f);

    rlMatrixMode(RL_MODELVIEW);         
    rlLoadIdentity();                   
}



static void SetupFramebuffer(int width, int height)
{
    
    if ((CORE.Window.screen.width > CORE.Window.display.width) || (CORE.Window.screen.height > CORE.Window.display.height))
    {
        TRACELOG(LOG_WARNING, "DISPLAY: Downscaling required: Screen size (%ix%i) is bigger than display size (%ix%i)", CORE.Window.screen.width, CORE.Window.screen.height, CORE.Window.display.width, CORE.Window.display.height);

        
        float widthRatio = (float)CORE.Window.display.width/(float)CORE.Window.screen.width;
        float heightRatio = (float)CORE.Window.display.height/(float)CORE.Window.screen.height;

        if (widthRatio <= heightRatio)
        {
            CORE.Window.render.width = CORE.Window.display.width;
            CORE.Window.render.height = (int)round((float)CORE.Window.screen.height*widthRatio);
            CORE.Window.renderOffset.x = 0;
            CORE.Window.renderOffset.y = (CORE.Window.display.height - CORE.Window.render.height);
        }
        else {
            CORE.Window.render.width = (int)round((float)CORE.Window.screen.width*heightRatio);
            CORE.Window.render.height = CORE.Window.display.height;
            CORE.Window.renderOffset.x = (CORE.Window.display.width - CORE.Window.render.width);
            CORE.Window.renderOffset.y = 0;
        }

        
        float scaleRatio = (float)CORE.Window.render.width/(float)CORE.Window.screen.width;
        CORE.Window.screenScale = MatrixScale(scaleRatio, scaleRatio, 1.0f);

        
        
        CORE.Window.render.width = CORE.Window.display.width;
        CORE.Window.render.height = CORE.Window.display.height;

        TRACELOG(LOG_WARNING, "DISPLAY: Downscale matrix generated, content will be rendered at (%ix%i)", CORE.Window.render.width, CORE.Window.render.height);
    }
    else if ((CORE.Window.screen.width < CORE.Window.display.width) || (CORE.Window.screen.height < CORE.Window.display.height))
    {
        
        TRACELOG(LOG_INFO, "DISPLAY: Upscaling required: Screen size (%ix%i) smaller than display size (%ix%i)", CORE.Window.screen.width, CORE.Window.screen.height, CORE.Window.display.width, CORE.Window.display.height);

        if ((CORE.Window.screen.width == 0) || (CORE.Window.screen.height == 0))
        {
            CORE.Window.screen.width = CORE.Window.display.width;
            CORE.Window.screen.height = CORE.Window.display.height;
        }

        
        float displayRatio = (float)CORE.Window.display.width/(float)CORE.Window.display.height;
        float screenRatio = (float)CORE.Window.screen.width/(float)CORE.Window.screen.height;

        if (displayRatio <= screenRatio)
        {
            CORE.Window.render.width = CORE.Window.screen.width;
            CORE.Window.render.height = (int)round((float)CORE.Window.screen.width/displayRatio);
            CORE.Window.renderOffset.x = 0;
            CORE.Window.renderOffset.y = (CORE.Window.render.height - CORE.Window.screen.height);
        }
        else {
            CORE.Window.render.width = (int)round((float)CORE.Window.screen.height*displayRatio);
            CORE.Window.render.height = CORE.Window.screen.height;
            CORE.Window.renderOffset.x = (CORE.Window.render.width - CORE.Window.screen.width);
            CORE.Window.renderOffset.y = 0;
        }
    }
    else {
        CORE.Window.render.width = CORE.Window.screen.width;
        CORE.Window.render.height = CORE.Window.screen.height;
        CORE.Window.renderOffset.x = 0;
        CORE.Window.renderOffset.y = 0;
    }
}


static void InitTimer(void)
{





    timeBeginPeriod(1);                 



    struct timespec now = { 0 };

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)  
    {
        CORE.Time.base = (unsigned long long int)now.tv_sec*1000000000LLU + (unsigned long long int)now.tv_nsec;
    }
    else TRACELOG(LOG_WARNING, "TIMER: Hi-resolution timer not available");


    CORE.Time.previous = GetTime();     
}






void WaitTime(double seconds)
{

    double destinationTime = GetTime() + seconds;



    while (GetTime() < destinationTime) { }

    #if defined(SUPPORT_PARTIALBUSY_WAIT_LOOP)
        double sleepSeconds = seconds - seconds*0.05;  
    #else
        double sleepSeconds = seconds;
    #endif

    
    #if defined(_WIN32)
        Sleep((unsigned long)(sleepSeconds*1000.0));
    #endif
    #if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__EMSCRIPTEN__)
        struct timespec req = { 0 };
        time_t sec = sleepSeconds;
        long nsec = (sleepSeconds - sec)*1000000000L;
        req.tv_sec = sec;
        req.tv_nsec = nsec;

        
        while (nanosleep(&req, &req) == -1) continue;
    #endif
    #if defined(__APPLE__)
        usleep(sleepSeconds*1000000.0);
    #endif

    #if defined(SUPPORT_PARTIALBUSY_WAIT_LOOP)
        while (GetTime() < destinationTime) { }
    #endif

}


void SwapScreenBuffer(void)
{

    glfwSwapBuffers(CORE.Window.handle);



    eglSwapBuffers(CORE.Window.device, CORE.Window.surface);



    if (!CORE.Window.gbmSurface || (-1 == CORE.Window.fd) || !CORE.Window.connector || !CORE.Window.crtc) TRACELOG(LOG_ERROR, "DISPLAY: DRM initialization failed to swap");

    struct gbm_bo *bo = gbm_surface_lock_front_buffer(CORE.Window.gbmSurface);
    if (!bo) TRACELOG(LOG_ERROR, "DISPLAY: Failed GBM to lock front buffer");

    uint32_t fb = 0;
    int result = drmModeAddFB(CORE.Window.fd, CORE.Window.connector->modes[CORE.Window.modeIndex].hdisplay, CORE.Window.connector->modes[CORE.Window.modeIndex].vdisplay, 24, 32, gbm_bo_get_stride(bo), gbm_bo_get_handle(bo).u32, &fb);
    if (result != 0) TRACELOG(LOG_ERROR, "DISPLAY: drmModeAddFB() failed with result: %d", result);

    result = drmModeSetCrtc(CORE.Window.fd, CORE.Window.crtc->crtc_id, fb, 0, 0, &CORE.Window.connector->connector_id, 1, &CORE.Window.connector->modes[CORE.Window.modeIndex]);
    if (result != 0) TRACELOG(LOG_ERROR, "DISPLAY: drmModeSetCrtc() failed with result: %d", result);

    if (CORE.Window.prevFB)
    {
        result = drmModeRmFB(CORE.Window.fd, CORE.Window.prevFB);
        if (result != 0) TRACELOG(LOG_ERROR, "DISPLAY: drmModeRmFB() failed with result: %d", result);
    }

    CORE.Window.prevFB = fb;

    if (CORE.Window.prevBO) gbm_surface_release_buffer(CORE.Window.gbmSurface, CORE.Window.prevBO);

    CORE.Window.prevBO = bo;



}


void PollInputEvents(void)
{

    
    
    UpdateGestures();


    
    CORE.Input.Keyboard.keyPressedQueueCount = 0;
    CORE.Input.Keyboard.charPressedQueueCount = 0;


    
    CORE.Input.Gamepad.lastButtonPressed = 0;       
    CORE.Input.Gamepad.axisCount = 0;



    
    for (int i = 0; i < MAX_KEYBOARD_KEYS; i++) CORE.Input.Keyboard.previousKeyState[i] = CORE.Input.Keyboard.currentKeyState[i];

    PollKeyboardEvents();

    
    CORE.Input.Mouse.previousWheelMove = CORE.Input.Mouse.currentWheelMove;
    CORE.Input.Mouse.currentWheelMove = (Vector2){ 0.0f, 0.0f };
    for (int i = 0; i < MAX_MOUSE_BUTTONS; i++)
    {
        CORE.Input.Mouse.previousButtonState[i] = CORE.Input.Mouse.currentButtonState[i];
        CORE.Input.Mouse.currentButtonState[i] = CORE.Input.Mouse.currentButtonStateEvdev[i];
    }

    
    for (int i = 0; i < MAX_GAMEPADS; i++)
    {
        if (CORE.Input.Gamepad.ready[i])
        {
            
            for (int k = 0; k < MAX_GAMEPAD_BUTTONS; k++) CORE.Input.Gamepad.previousButtonState[i][k] = CORE.Input.Gamepad.currentButtonState[i][k];
        }
    }



    

    
    for (int i = 0; i < MAX_KEYBOARD_KEYS; i++) CORE.Input.Keyboard.previousKeyState[i] = CORE.Input.Keyboard.currentKeyState[i];

    
    for (int i = 0; i < MAX_MOUSE_BUTTONS; i++) CORE.Input.Mouse.previousButtonState[i] = CORE.Input.Mouse.currentButtonState[i];

    
    CORE.Input.Mouse.previousWheelMove = CORE.Input.Mouse.currentWheelMove;
    CORE.Input.Mouse.currentWheelMove = (Vector2){ 0.0f, 0.0f };

    
    CORE.Input.Mouse.previousPosition = CORE.Input.Mouse.currentPosition;


    
    for (int i = 0; i < MAX_TOUCH_POINTS; i++) CORE.Input.Touch.previousTouchState[i] = CORE.Input.Touch.currentTouchState[i];

    
    
    
    


    
    
    for (int i = 0; i < MAX_GAMEPADS; i++)
    {
        if (glfwJoystickPresent(i)) CORE.Input.Gamepad.ready[i] = true;
        else CORE.Input.Gamepad.ready[i] = false;
    }

    
    for (int i = 0; i < MAX_GAMEPADS; i++)
    {
        if (CORE.Input.Gamepad.ready[i])     
        {
            
            for (int k = 0; k < MAX_GAMEPAD_BUTTONS; k++) CORE.Input.Gamepad.previousButtonState[i][k] = CORE.Input.Gamepad.currentButtonState[i][k];

            
            
            
            GLFWgamepadstate state = { 0 };
            glfwGetGamepadState(i, &state); 

            const unsigned char *buttons = state.buttons;

            for (int k = 0; (buttons != NULL) && (k < GLFW_GAMEPAD_BUTTON_DPAD_LEFT + 1) && (k < MAX_GAMEPAD_BUTTONS); k++)
            {
                GamepadButton button = -1;

                switch (k)
                {
                    case GLFW_GAMEPAD_BUTTON_Y: button = GAMEPAD_BUTTON_RIGHT_FACE_UP; break;
                    case GLFW_GAMEPAD_BUTTON_B: button = GAMEPAD_BUTTON_RIGHT_FACE_RIGHT; break;
                    case GLFW_GAMEPAD_BUTTON_A: button = GAMEPAD_BUTTON_RIGHT_FACE_DOWN; break;
                    case GLFW_GAMEPAD_BUTTON_X: button = GAMEPAD_BUTTON_RIGHT_FACE_LEFT; break;

                    case GLFW_GAMEPAD_BUTTON_LEFT_BUMPER: button = GAMEPAD_BUTTON_LEFT_TRIGGER_1; break;
                    case GLFW_GAMEPAD_BUTTON_RIGHT_BUMPER: button = GAMEPAD_BUTTON_RIGHT_TRIGGER_1; break;

                    case GLFW_GAMEPAD_BUTTON_BACK: button = GAMEPAD_BUTTON_MIDDLE_LEFT; break;
                    case GLFW_GAMEPAD_BUTTON_GUIDE: button = GAMEPAD_BUTTON_MIDDLE; break;
                    case GLFW_GAMEPAD_BUTTON_START: button = GAMEPAD_BUTTON_MIDDLE_RIGHT; break;

                    case GLFW_GAMEPAD_BUTTON_DPAD_UP: button = GAMEPAD_BUTTON_LEFT_FACE_UP; break;
                    case GLFW_GAMEPAD_BUTTON_DPAD_RIGHT: button = GAMEPAD_BUTTON_LEFT_FACE_RIGHT; break;
                    case GLFW_GAMEPAD_BUTTON_DPAD_DOWN: button = GAMEPAD_BUTTON_LEFT_FACE_DOWN; break;
                    case GLFW_GAMEPAD_BUTTON_DPAD_LEFT: button = GAMEPAD_BUTTON_LEFT_FACE_LEFT; break;

                    case GLFW_GAMEPAD_BUTTON_LEFT_THUMB: button = GAMEPAD_BUTTON_LEFT_THUMB; break;
                    case GLFW_GAMEPAD_BUTTON_RIGHT_THUMB: button = GAMEPAD_BUTTON_RIGHT_THUMB; break;
                    default: break;
                }

                if (button != -1)   
                {
                    if (buttons[k] == GLFW_PRESS)
                    {
                        CORE.Input.Gamepad.currentButtonState[i][button] = 1;
                        CORE.Input.Gamepad.lastButtonPressed = button;
                    }
                    else CORE.Input.Gamepad.currentButtonState[i][button] = 0;
                }
            }

            
            const float *axes = state.axes;

            for (int k = 0; (axes != NULL) && (k < GLFW_GAMEPAD_AXIS_LAST + 1) && (k < MAX_GAMEPAD_AXIS); k++)
            {
                CORE.Input.Gamepad.axisState[i][k] = axes[k];
            }

            
            CORE.Input.Gamepad.currentButtonState[i][GAMEPAD_BUTTON_LEFT_TRIGGER_2] = (char)(CORE.Input.Gamepad.axisState[i][GAMEPAD_AXIS_LEFT_TRIGGER] > 0.1f);
            CORE.Input.Gamepad.currentButtonState[i][GAMEPAD_BUTTON_RIGHT_TRIGGER_2] = (char)(CORE.Input.Gamepad.axisState[i][GAMEPAD_AXIS_RIGHT_TRIGGER] > 0.1f);

            CORE.Input.Gamepad.axisCount = GLFW_GAMEPAD_AXIS_LAST + 1;
        }
    }

    CORE.Window.resizedLastFrame = false;

    if (CORE.Window.eventWaiting) glfwWaitEvents();     
    else glfwPollEvents();      



    CORE.Window.resizedLastFrame = false;





    
    int numGamepads = 0;
    if (emscripten_sample_gamepad_data() == EMSCRIPTEN_RESULT_SUCCESS) numGamepads = emscripten_get_num_gamepads();

    for (int i = 0; (i < numGamepads) && (i < MAX_GAMEPADS); i++)
    {
        
        for (int k = 0; k < MAX_GAMEPAD_BUTTONS; k++) CORE.Input.Gamepad.previousButtonState[i][k] = CORE.Input.Gamepad.currentButtonState[i][k];

        EmscriptenGamepadEvent gamepadState;

        int result = emscripten_get_gamepad_status(i, &gamepadState);

        if (result == EMSCRIPTEN_RESULT_SUCCESS)
        {
            
            for (int j = 0; (j < gamepadState.numButtons) && (j < MAX_GAMEPAD_BUTTONS); j++)
            {
                GamepadButton button = -1;

                
                switch (j)
                {
                    case 0: button = GAMEPAD_BUTTON_RIGHT_FACE_DOWN; break;
                    case 1: button = GAMEPAD_BUTTON_RIGHT_FACE_RIGHT; break;
                    case 2: button = GAMEPAD_BUTTON_RIGHT_FACE_LEFT; break;
                    case 3: button = GAMEPAD_BUTTON_RIGHT_FACE_UP; break;
                    case 4: button = GAMEPAD_BUTTON_LEFT_TRIGGER_1; break;
                    case 5: button = GAMEPAD_BUTTON_RIGHT_TRIGGER_1; break;
                    case 6: button = GAMEPAD_BUTTON_LEFT_TRIGGER_2; break;
                    case 7: button = GAMEPAD_BUTTON_RIGHT_TRIGGER_2; break;
                    case 8: button = GAMEPAD_BUTTON_MIDDLE_LEFT; break;
                    case 9: button = GAMEPAD_BUTTON_MIDDLE_RIGHT; break;
                    case 10: button = GAMEPAD_BUTTON_LEFT_THUMB; break;
                    case 11: button = GAMEPAD_BUTTON_RIGHT_THUMB; break;
                    case 12: button = GAMEPAD_BUTTON_LEFT_FACE_UP; break;
                    case 13: button = GAMEPAD_BUTTON_LEFT_FACE_DOWN; break;
                    case 14: button = GAMEPAD_BUTTON_LEFT_FACE_LEFT; break;
                    case 15: button = GAMEPAD_BUTTON_LEFT_FACE_RIGHT; break;
                    default: break;
                }

                if (button != -1)   
                {
                    if (gamepadState.digitalButton[j] == 1)
                    {
                        CORE.Input.Gamepad.currentButtonState[i][button] = 1;
                        CORE.Input.Gamepad.lastButtonPressed = button;
                    }
                    else CORE.Input.Gamepad.currentButtonState[i][button] = 0;
                }

                
            }

            
            for (int j = 0; (j < gamepadState.numAxes) && (j < MAX_GAMEPAD_AXIS); j++)
            {
                CORE.Input.Gamepad.axisState[i][j] = gamepadState.axis[j];
            }

            CORE.Input.Gamepad.axisCount = gamepadState.numAxes;
        }
    }



    
    
    for (int i = 0; i < 260; i++) CORE.Input.Keyboard.previousKeyState[i] = CORE.Input.Keyboard.currentKeyState[i];

    
    int pollResult = 0;
    int pollEvents = 0;

    
    
    while ((pollResult = ALooper_pollAll(CORE.Android.appEnabled? 0 : -1, NULL, &pollEvents, (void**)&CORE.Android.source)) >= 0)
    {
        
        if (CORE.Android.source != NULL) CORE.Android.source->process(CORE.Android.app, CORE.Android.source);

        
        if (CORE.Android.app->destroyRequested != 0)
        {
            
            
        }
    }



    
    

    if (!CORE.Input.Keyboard.evtMode) ProcessKeyboard();

    
    

}




static void ScanDirectoryFiles(const char *basePath, FilePathList *files, const char *filter)
{
    static char path[MAX_FILEPATH_LENGTH] = { 0 };
    memset(path, 0, MAX_FILEPATH_LENGTH);

    struct dirent *dp = NULL;
    DIR *dir = opendir(basePath);

    if (dir != NULL)
    {
        while ((dp = readdir(dir)) != NULL)
        {
            if ((strcmp(dp->d_name, ".") != 0) && (strcmp(dp->d_name, "..") != 0))
            {
                sprintf(path, "%s/%s", basePath, dp->d_name);

                if (filter != NULL)
                {
                    if (IsFileExtension(path, filter))
                    {
                        strcpy(files->paths[files->count], path);
                        files->count++;
                    }
                }
                else {
                    strcpy(files->paths[files->count], path);
                    files->count++;
                }
            }
        }

        closedir(dir);
    }
    else TRACELOG(LOG_WARNING, "FILEIO: Directory cannot be opened (%s)", basePath);
}


static void ScanDirectoryFilesRecursively(const char *basePath, FilePathList *files, const char *filter)
{
    char path[MAX_FILEPATH_LENGTH] = { 0 };
    memset(path, 0, MAX_FILEPATH_LENGTH);

    struct dirent *dp = NULL;
    DIR *dir = opendir(basePath);

    if (dir != NULL)
    {
        while (((dp = readdir(dir)) != NULL) && (files->count < files->capacity))
        {
            if ((strcmp(dp->d_name, ".") != 0) && (strcmp(dp->d_name, "..") != 0))
            {
                
                sprintf(path, "%s/%s", basePath, dp->d_name);

                if (IsPathFile(path))
                {
                    if (filter != NULL)
                    {
                        if (IsFileExtension(path, filter))
                        {
                            strcpy(files->paths[files->count], path);
                            files->count++;
                        }
                    }
                    else {
                        strcpy(files->paths[files->count], path);
                        files->count++;
                    }

                    if (files->count >= files->capacity)
                    {
                        TRACELOG(LOG_WARNING, "FILEIO: Maximum filepath scan capacity reached (%i files)", files->capacity);
                        break;
                    }
                }
                else ScanDirectoryFilesRecursively(path, files, filter);
            }
        }

        closedir(dir);
    }
    else TRACELOG(LOG_WARNING, "FILEIO: Directory cannot be opened (%s)", basePath);
}



static void ErrorCallback(int error, const char *description)
{
    TRACELOG(LOG_WARNING, "GLFW: Error: %i Description: %s", error, description);
}



static void WindowSizeCallback(GLFWwindow *window, int width, int height)
{
    
    SetupViewport(width, height);

    CORE.Window.currentFbo.width = width;
    CORE.Window.currentFbo.height = height;
    CORE.Window.resizedLastFrame = true;

    if (IsWindowFullscreen()) return;

    

    CORE.Window.screen.width = width;
    CORE.Window.screen.height = height;

    if ((CORE.Window.flags & FLAG_WINDOW_HIGHDPI) > 0)
    {
        Vector2 windowScaleDPI = GetWindowScaleDPI();

        CORE.Window.screen.width = (unsigned int)(width/windowScaleDPI.x);
        CORE.Window.screen.height = (unsigned int)(height/windowScaleDPI.y);
    }
    else {
        CORE.Window.screen.width = width;
        CORE.Window.screen.height = height;
    }


    
}


static void WindowIconifyCallback(GLFWwindow *window, int iconified)
{
    if (iconified) CORE.Window.flags |= FLAG_WINDOW_MINIMIZED;  
    else CORE.Window.flags &= ~FLAG_WINDOW_MINIMIZED;           
}



static void WindowMaximizeCallback(GLFWwindow *window, int maximized)
{
    if (maximized) CORE.Window.flags |= FLAG_WINDOW_MAXIMIZED;  
    else CORE.Window.flags &= ~FLAG_WINDOW_MAXIMIZED;           
}



static void WindowFocusCallback(GLFWwindow *window, int focused)
{
    if (focused) CORE.Window.flags &= ~FLAG_WINDOW_UNFOCUSED;   
    else CORE.Window.flags |= FLAG_WINDOW_UNFOCUSED;            
}


static void KeyCallback(GLFWwindow *window, int key, int scancode, int action, int mods)
{
    if (key < 0) return;    

    
    
    if (action == GLFW_RELEASE) CORE.Input.Keyboard.currentKeyState[key] = 0;
    else CORE.Input.Keyboard.currentKeyState[key] = 1;


    
    if (((key == KEY_CAPS_LOCK) && ((mods & GLFW_MOD_CAPS_LOCK) > 0)) || ((key == KEY_NUM_LOCK) && ((mods & GLFW_MOD_NUM_LOCK) > 0))) CORE.Input.Keyboard.currentKeyState[key] = 1;


    
    if ((CORE.Input.Keyboard.keyPressedQueueCount < MAX_KEY_PRESSED_QUEUE) && (action == GLFW_PRESS))
    {
        
        CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount] = key;
        CORE.Input.Keyboard.keyPressedQueueCount++;
    }

    
    if ((key == CORE.Input.Keyboard.exitKey) && (action == GLFW_PRESS)) glfwSetWindowShouldClose(CORE.Window.handle, GLFW_TRUE);


    if ((key == GLFW_KEY_F12) && (action == GLFW_PRESS))
    {

        if (mods == GLFW_MOD_CONTROL)
        {
            if (gifRecording)
            {
                gifRecording = false;

                MsfGifResult result = msf_gif_end(&gifState);

                SaveFileData(TextFormat("%s/screenrec%03i.gif", CORE.Storage.basePath, screenshotCounter), result.data, (unsigned int)result.dataSize);
                msf_gif_free(result);

            #if defined(PLATFORM_WEB)
                
                
                emscripten_run_script(TextFormat("saveFileFromMEMFSToDisk('%s','%s')", TextFormat("screenrec%03i.gif", screenshotCounter - 1), TextFormat("screenrec%03i.gif", screenshotCounter - 1)));
            #endif

                TRACELOG(LOG_INFO, "SYSTEM: Finish animated GIF recording");
            }
            else {
                gifRecording = true;
                gifFrameCounter = 0;

                Vector2 scale = GetWindowScaleDPI();
                msf_gif_begin(&gifState, (int)((float)CORE.Window.render.width*scale.x), (int)((float)CORE.Window.render.height*scale.y));
                screenshotCounter++;

                TRACELOG(LOG_INFO, "SYSTEM: Start animated GIF recording: %s", TextFormat("screenrec%03i.gif", screenshotCounter));
            }
        }
        else  {

            TakeScreenshot(TextFormat("screenshot%03i.png", screenshotCounter));
            screenshotCounter++;
        }
    }



    if ((key == GLFW_KEY_F11) && (action == GLFW_PRESS))
    {
        eventsRecording = !eventsRecording;

        
        if (!eventsRecording) ExportAutomationEvents("eventsrec.rep");
    }
    else if ((key == GLFW_KEY_F9) && (action == GLFW_PRESS))
    {
        LoadAutomationEvents("eventsrec.rep");
        eventsPlaying = true;

        TRACELOG(LOG_WARNING, "eventsPlaying enabled!");
    }

}


static void CharCallback(GLFWwindow *window, unsigned int key)
{
    

    
    
    
    

    
    if (CORE.Input.Keyboard.charPressedQueueCount < MAX_CHAR_PRESSED_QUEUE)
    {
        
        CORE.Input.Keyboard.charPressedQueue[CORE.Input.Keyboard.charPressedQueueCount] = key;
        CORE.Input.Keyboard.charPressedQueueCount++;
    }
}


static void MouseButtonCallback(GLFWwindow *window, int button, int action, int mods)
{
    
    
    CORE.Input.Mouse.currentButtonState[button] = action;


    
    GestureEvent gestureEvent = { 0 };

    
    if ((CORE.Input.Mouse.currentButtonState[button] == 1) && (CORE.Input.Mouse.previousButtonState[button] == 0)) gestureEvent.touchAction = TOUCH_ACTION_DOWN;
    else if ((CORE.Input.Mouse.currentButtonState[button] == 0) && (CORE.Input.Mouse.previousButtonState[button] == 1)) gestureEvent.touchAction = TOUCH_ACTION_UP;

    

    
    gestureEvent.pointId[0] = 0;

    
    gestureEvent.pointCount = 1;

    
    gestureEvent.position[0] = GetMousePosition();

    
    gestureEvent.position[0].x /= (float)GetScreenWidth();
    gestureEvent.position[0].y /= (float)GetScreenHeight();

    
    ProcessGestureEvent(gestureEvent);

}


static void MouseCursorPosCallback(GLFWwindow *window, double x, double y)
{
    CORE.Input.Mouse.currentPosition.x = (float)x;
    CORE.Input.Mouse.currentPosition.y = (float)y;
    CORE.Input.Touch.position[0] = CORE.Input.Mouse.currentPosition;


    
    GestureEvent gestureEvent = { 0 };

    gestureEvent.touchAction = TOUCH_ACTION_MOVE;

    
    gestureEvent.pointId[0] = 0;

    
    gestureEvent.pointCount = 1;

    
    gestureEvent.position[0] = CORE.Input.Touch.position[0];

    
    gestureEvent.position[0].x /= (float)GetScreenWidth();
    gestureEvent.position[0].y /= (float)GetScreenHeight();

    
    ProcessGestureEvent(gestureEvent);

}


static void MouseScrollCallback(GLFWwindow *window, double xoffset, double yoffset)
{
    CORE.Input.Mouse.currentWheelMove = (Vector2){ (float)xoffset, (float)yoffset };
}


static void CursorEnterCallback(GLFWwindow *window, int enter)
{
    if (enter == true) CORE.Input.Mouse.cursorOnScreen = true;
    else CORE.Input.Mouse.cursorOnScreen = false;
}


static void WindowDropCallback(GLFWwindow *window, int count, const char **paths)
{
    if (count > 0)
    {
        
        if (CORE.Window.dropFileCount > 0)
        {
            for (unsigned int i = 0; i < CORE.Window.dropFileCount; i++) RL_FREE(CORE.Window.dropFilepaths[i]);

            RL_FREE(CORE.Window.dropFilepaths);

            CORE.Window.dropFileCount = 0;
            CORE.Window.dropFilepaths = NULL;
        }

        
        CORE.Window.dropFileCount = count;
        CORE.Window.dropFilepaths = (char **)RL_CALLOC(CORE.Window.dropFileCount, sizeof(char *));

        for (unsigned int i = 0; i < CORE.Window.dropFileCount; i++)
        {
            CORE.Window.dropFilepaths[i] = (char *)RL_CALLOC(MAX_FILEPATH_LENGTH, sizeof(char));
            strcpy(CORE.Window.dropFilepaths[i], paths[i]);
        }
    }
}




static void AndroidCommandCallback(struct android_app *app, int32_t cmd)
{
    switch (cmd)
    {
        case APP_CMD_START:
        {
            
        } break;
        case APP_CMD_RESUME: break;
        case APP_CMD_INIT_WINDOW:
        {
            if (app->window != NULL)
            {
                if (CORE.Android.contextRebindRequired)
                {
                    
                    EGLint displayFormat = 0;
                    eglGetConfigAttrib(CORE.Window.device, CORE.Window.config, EGL_NATIVE_VISUAL_ID, &displayFormat);

                    
                    
                    
                    ANativeWindow_setBuffersGeometry(app->window, CORE.Window.render.width + CORE.Window.renderOffset.x, CORE.Window.render.height + CORE.Window.renderOffset.y, displayFormat);



                    
                    CORE.Window.surface = eglCreateWindowSurface(CORE.Window.device, CORE.Window.config, app->window, NULL);
                    eglMakeCurrent(CORE.Window.device, CORE.Window.surface, CORE.Window.surface, CORE.Window.context);

                    CORE.Android.contextRebindRequired = false;
                }
                else {
                    CORE.Window.display.width = ANativeWindow_getWidth(CORE.Android.app->window);
                    CORE.Window.display.height = ANativeWindow_getHeight(CORE.Android.app->window);

                    
                    InitGraphicsDevice(CORE.Window.screen.width, CORE.Window.screen.height);

                    
                    InitTimer();

                    
                    srand((unsigned int)time(NULL));

                #if defined(SUPPORT_MODULE_RTEXT) && defined(SUPPORT_DEFAULT_FONT)
                    
                    
                    LoadFontDefault();
                    Rectangle rec = GetFontDefault().recs[95];
                    
                    #if defined(SUPPORT_MODULE_RSHAPES)
                    SetShapesTexture(GetFontDefault().texture, (Rectangle){ rec.x + 1, rec.y + 1, rec.width - 2, rec.height - 2 });  
                    #endif
                #endif

                    
                    
                    
                }
            }
        } break;
        case APP_CMD_GAINED_FOCUS:
        {
            CORE.Android.appEnabled = true;
            
        } break;
        case APP_CMD_PAUSE: break;
        case APP_CMD_LOST_FOCUS:
        {
            CORE.Android.appEnabled = false;
            
        } break;
        case APP_CMD_TERM_WINDOW:
        {
            
            
            
            eglMakeCurrent(CORE.Window.device, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
            eglDestroySurface(CORE.Window.device, CORE.Window.surface);

            CORE.Android.contextRebindRequired = true;
        } break;
        case APP_CMD_SAVE_STATE: break;
        case APP_CMD_STOP: break;
        case APP_CMD_DESTROY:
        {
            
            
        } break;
        case APP_CMD_CONFIG_CHANGED:
        {
            
            

            
        } break;
        default: break;
    }
}

static GamepadButton AndroidTranslateGamepadButton(int button)
{
    switch (button)
    {
        case AKEYCODE_BUTTON_A: return GAMEPAD_BUTTON_RIGHT_FACE_DOWN;
        case AKEYCODE_BUTTON_B: return GAMEPAD_BUTTON_RIGHT_FACE_RIGHT;
        case AKEYCODE_BUTTON_X: return GAMEPAD_BUTTON_RIGHT_FACE_LEFT;
        case AKEYCODE_BUTTON_Y: return GAMEPAD_BUTTON_RIGHT_FACE_UP;
        case AKEYCODE_BUTTON_L1: return GAMEPAD_BUTTON_LEFT_TRIGGER_1;
        case AKEYCODE_BUTTON_R1: return GAMEPAD_BUTTON_RIGHT_TRIGGER_1;
        case AKEYCODE_BUTTON_L2: return GAMEPAD_BUTTON_LEFT_TRIGGER_2;
        case AKEYCODE_BUTTON_R2: return GAMEPAD_BUTTON_RIGHT_TRIGGER_2;
        case AKEYCODE_BUTTON_THUMBL: return GAMEPAD_BUTTON_LEFT_THUMB;
        case AKEYCODE_BUTTON_THUMBR: return GAMEPAD_BUTTON_RIGHT_THUMB;
        case AKEYCODE_BUTTON_START: return GAMEPAD_BUTTON_MIDDLE_RIGHT;
        case AKEYCODE_BUTTON_SELECT: return GAMEPAD_BUTTON_MIDDLE_LEFT;
        case AKEYCODE_BUTTON_MODE: return GAMEPAD_BUTTON_MIDDLE;
        
        case AKEYCODE_DPAD_DOWN: return GAMEPAD_BUTTON_LEFT_FACE_DOWN;
        case AKEYCODE_DPAD_RIGHT: return GAMEPAD_BUTTON_LEFT_FACE_RIGHT;
        case AKEYCODE_DPAD_LEFT: return GAMEPAD_BUTTON_LEFT_FACE_LEFT;
        case AKEYCODE_DPAD_UP: return GAMEPAD_BUTTON_LEFT_FACE_UP;
        default: return GAMEPAD_BUTTON_UNKNOWN;
    }
}


static int32_t AndroidInputCallback(struct android_app *app, AInputEvent *event)
{
    
    
    

    int type = AInputEvent_getType(event);
    int source = AInputEvent_getSource(event);

    if (type == AINPUT_EVENT_TYPE_MOTION)
    {
        if (((source & AINPUT_SOURCE_JOYSTICK) == AINPUT_SOURCE_JOYSTICK) || ((source & AINPUT_SOURCE_GAMEPAD) == AINPUT_SOURCE_GAMEPAD))
        {
            
            CORE.Input.Gamepad.ready[0] = true;

            CORE.Input.Gamepad.axisState[0][GAMEPAD_AXIS_LEFT_X] = AMotionEvent_getAxisValue( event, AMOTION_EVENT_AXIS_X, 0);
            CORE.Input.Gamepad.axisState[0][GAMEPAD_AXIS_LEFT_Y] = AMotionEvent_getAxisValue( event, AMOTION_EVENT_AXIS_Y, 0);
            CORE.Input.Gamepad.axisState[0][GAMEPAD_AXIS_RIGHT_X] = AMotionEvent_getAxisValue( event, AMOTION_EVENT_AXIS_Z, 0);
            CORE.Input.Gamepad.axisState[0][GAMEPAD_AXIS_RIGHT_Y] = AMotionEvent_getAxisValue( event, AMOTION_EVENT_AXIS_RZ, 0);
            CORE.Input.Gamepad.axisState[0][GAMEPAD_AXIS_LEFT_TRIGGER] = AMotionEvent_getAxisValue( event, AMOTION_EVENT_AXIS_BRAKE, 0) * 2.0f - 1.0f;
            CORE.Input.Gamepad.axisState[0][GAMEPAD_AXIS_RIGHT_TRIGGER] = AMotionEvent_getAxisValue( event, AMOTION_EVENT_AXIS_GAS, 0) * 2.0f - 1.0f;

            
            float dpadX = AMotionEvent_getAxisValue(event, AMOTION_EVENT_AXIS_HAT_X, 0);
            float dpadY = AMotionEvent_getAxisValue(event, AMOTION_EVENT_AXIS_HAT_Y, 0);

            if (dpadX == 1.0f)
            {
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_RIGHT] = 1;
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_LEFT] = 0;
            }
            else if (dpadX == -1.0f)
            {
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_RIGHT] = 0;
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_LEFT] = 1;
            }
            else {
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_RIGHT] = 0;
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_LEFT] = 0;
            }

            if (dpadY == 1.0f)
            {
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_DOWN] = 1;
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_UP] = 0;
            }
            else if (dpadY == -1.0f)
            {
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_DOWN] = 0;
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_UP] = 1;
            }
            else {
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_DOWN] = 0;
                CORE.Input.Gamepad.currentButtonState[0][GAMEPAD_BUTTON_LEFT_FACE_UP] = 0;
            }

            return 1; 
        }
    }
    else if (type == AINPUT_EVENT_TYPE_KEY)
    {
        int32_t keycode = AKeyEvent_getKeyCode(event);
        

        
        if (((source & AINPUT_SOURCE_JOYSTICK) == AINPUT_SOURCE_JOYSTICK) || ((source & AINPUT_SOURCE_GAMEPAD) == AINPUT_SOURCE_GAMEPAD))
        {
            
            CORE.Input.Gamepad.ready[0] = true;

            GamepadButton button = AndroidTranslateGamepadButton(keycode);

            if (button == GAMEPAD_BUTTON_UNKNOWN) return 1;

            if (AKeyEvent_getAction(event) == AKEY_EVENT_ACTION_DOWN)
            {
                CORE.Input.Gamepad.currentButtonState[0][button] = 1;
            }
            else CORE.Input.Gamepad.currentButtonState[0][button] = 0;  

            return 1; 
        }

        
        
        if (AKeyEvent_getAction(event) == AKEY_EVENT_ACTION_DOWN)
        {
            CORE.Input.Keyboard.currentKeyState[keycode] = 1;   

            CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount] = keycode;
            CORE.Input.Keyboard.keyPressedQueueCount++;
        }
        else CORE.Input.Keyboard.currentKeyState[keycode] = 0;  

        if (keycode == AKEYCODE_POWER)
        {
            
            
            
            
            
            return 0;
        }
        else if ((keycode == AKEYCODE_BACK) || (keycode == AKEYCODE_MENU))
        {
            
            return 1;
        }
        else if ((keycode == AKEYCODE_VOLUME_UP) || (keycode == AKEYCODE_VOLUME_DOWN))
        {
            
            return 0;
        }

        return 0;
    }

    
    CORE.Input.Touch.pointCount = AMotionEvent_getPointerCount(event);

    for (int i = 0; (i < CORE.Input.Touch.pointCount) && (i < MAX_TOUCH_POINTS); i++)
    {
        
        CORE.Input.Touch.pointId[i] = AMotionEvent_getPointerId(event, i);

        
        CORE.Input.Touch.position[i] = (Vector2){ AMotionEvent_getX(event, i), AMotionEvent_getY(event, i) };

        
        float widthRatio = (float)(CORE.Window.screen.width + CORE.Window.renderOffset.x) / (float)CORE.Window.display.width;
        float heightRatio = (float)(CORE.Window.screen.height + CORE.Window.renderOffset.y) / (float)CORE.Window.display.height;
        CORE.Input.Touch.position[i].x = CORE.Input.Touch.position[i].x * widthRatio - (float)CORE.Window.renderOffset.x / 2;
        CORE.Input.Touch.position[i].y = CORE.Input.Touch.position[i].y * heightRatio - (float)CORE.Window.renderOffset.y / 2;
    }

    int32_t action = AMotionEvent_getAction(event);
    unsigned int flags = action & AMOTION_EVENT_ACTION_MASK;


    GestureEvent gestureEvent = { 0 };

    gestureEvent.pointCount = CORE.Input.Touch.pointCount;

    
    if (flags == AMOTION_EVENT_ACTION_DOWN) gestureEvent.touchAction = TOUCH_ACTION_DOWN;
    else if (flags == AMOTION_EVENT_ACTION_UP) gestureEvent.touchAction = TOUCH_ACTION_UP;
    else if (flags == AMOTION_EVENT_ACTION_MOVE) gestureEvent.touchAction = TOUCH_ACTION_MOVE;
    else if (flags == AMOTION_EVENT_ACTION_CANCEL) gestureEvent.touchAction = TOUCH_ACTION_CANCEL;

    for (int i = 0; (i < gestureEvent.pointCount) && (i < MAX_TOUCH_POINTS); i++)
    {
        gestureEvent.pointId[i] = CORE.Input.Touch.pointId[i];
        gestureEvent.position[i] = CORE.Input.Touch.position[i];
    }

    
    ProcessGestureEvent(gestureEvent);


    int32_t pointerIndex = (action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK) >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;

    if (flags == AMOTION_EVENT_ACTION_POINTER_UP || flags == AMOTION_EVENT_ACTION_UP)
    {
        
        for (int i = pointerIndex; (i < CORE.Input.Touch.pointCount-1) && (i < MAX_TOUCH_POINTS); i++)
        {
            CORE.Input.Touch.pointId[i] = CORE.Input.Touch.pointId[i+1];
            CORE.Input.Touch.position[i] = CORE.Input.Touch.position[i+1];
        }
        CORE.Input.Touch.pointCount--;
    }

    
    if (flags == AMOTION_EVENT_ACTION_CANCEL) CORE.Input.Touch.pointCount = 0;

    if (CORE.Input.Touch.pointCount > 0) CORE.Input.Touch.currentTouchState[MOUSE_BUTTON_LEFT] = 1;
    else CORE.Input.Touch.currentTouchState[MOUSE_BUTTON_LEFT] = 0;

    return 0;
}




static EM_BOOL EmscriptenFullscreenChangeCallback(int eventType, const EmscriptenFullscreenChangeEvent *event, void *userData)
{
    

    return 1;   
}


static EM_BOOL EmscriptenWindowResizedCallback(int eventType, const EmscriptenUiEvent *event, void *userData)
{
    

    return 1;   
}

EM_JS(int, GetCanvasWidth, (), { return canvas.clientWidth; });
EM_JS(int, GetCanvasHeight, (), { return canvas.clientHeight; });


static EM_BOOL EmscriptenResizeCallback(int eventType, const EmscriptenUiEvent *event, void *userData)
{
    
    if ((CORE.Window.flags & FLAG_WINDOW_RESIZABLE) == 0) return 1;

    
    
    int width = GetCanvasWidth();
    int height = GetCanvasHeight();
    emscripten_set_canvas_element_size("#canvas",width,height);

    SetupViewport(width, height);    

    CORE.Window.currentFbo.width = width;
    CORE.Window.currentFbo.height = height;
    CORE.Window.resizedLastFrame = true;

    if (IsWindowFullscreen()) return 1;

    
    CORE.Window.screen.width = width;
    CORE.Window.screen.height = height;

    

    return 0;
}


static EM_BOOL EmscriptenMouseCallback(int eventType, const EmscriptenMouseEvent *mouseEvent, void *userData)
{
    

    return 1;   
}


static EM_BOOL EmscriptenGamepadCallback(int eventType, const EmscriptenGamepadEvent *gamepadEvent, void *userData)
{
    

    if ((gamepadEvent->connected) && (gamepadEvent->index < MAX_GAMEPADS))
    {
        CORE.Input.Gamepad.ready[gamepadEvent->index] = true;
        sprintf(CORE.Input.Gamepad.name[gamepadEvent->index],"%s",gamepadEvent->id);
    }
    else CORE.Input.Gamepad.ready[gamepadEvent->index] = false;

    return 1;   
}


static EM_BOOL EmscriptenTouchCallback(int eventType, const EmscriptenTouchEvent *touchEvent, void *userData)
{
    
    CORE.Input.Touch.pointCount = touchEvent->numTouches;

    double canvasWidth = 0.0;
    double canvasHeight = 0.0;
    
    
    
    emscripten_get_element_css_size("#canvas", &canvasWidth, &canvasHeight);

    for (int i = 0; (i < CORE.Input.Touch.pointCount) && (i < MAX_TOUCH_POINTS); i++)
    {
        
        CORE.Input.Touch.pointId[i] = touchEvent->touches[i].identifier;

        
        CORE.Input.Touch.position[i] = (Vector2){ touchEvent->touches[i].targetX, touchEvent->touches[i].targetY };

        
        CORE.Input.Touch.position[i].x *= ((float)GetScreenWidth()/(float)canvasWidth);
        CORE.Input.Touch.position[i].y *= ((float)GetScreenHeight()/(float)canvasHeight);

        if (eventType == EMSCRIPTEN_EVENT_TOUCHSTART) CORE.Input.Touch.currentTouchState[i] = 1;
        else if (eventType == EMSCRIPTEN_EVENT_TOUCHEND) CORE.Input.Touch.currentTouchState[i] = 0;
    }


    GestureEvent gestureEvent = { 0 };

    gestureEvent.pointCount = CORE.Input.Touch.pointCount;

    
    if (eventType == EMSCRIPTEN_EVENT_TOUCHSTART) gestureEvent.touchAction = TOUCH_ACTION_DOWN;
    else if (eventType == EMSCRIPTEN_EVENT_TOUCHEND) gestureEvent.touchAction = TOUCH_ACTION_UP;
    else if (eventType == EMSCRIPTEN_EVENT_TOUCHMOVE) gestureEvent.touchAction = TOUCH_ACTION_MOVE;
    else if (eventType == EMSCRIPTEN_EVENT_TOUCHCANCEL) gestureEvent.touchAction = TOUCH_ACTION_CANCEL;

    for (int i = 0; (i < gestureEvent.pointCount) && (i < MAX_TOUCH_POINTS); i++)
    {
        gestureEvent.pointId[i] = CORE.Input.Touch.pointId[i];
        gestureEvent.position[i] = CORE.Input.Touch.position[i];
    }

    
    ProcessGestureEvent(gestureEvent);


    return 1;   
}




static void InitKeyboard(void)
{
    
    

    
    tcgetattr(STDIN_FILENO, &CORE.Input.Keyboard.defaultSettings);

    
    struct termios keyboardNewSettings = { 0 };
    keyboardNewSettings = CORE.Input.Keyboard.defaultSettings;

    
    
    keyboardNewSettings.c_lflag &= ~(ICANON | ECHO | ISIG);
    
    keyboardNewSettings.c_cc[VMIN] = 1;
    keyboardNewSettings.c_cc[VTIME] = 0;

    
    tcsetattr(STDIN_FILENO, TCSANOW, &keyboardNewSettings);

    
    CORE.Input.Keyboard.defaultFileFlags = fcntl(STDIN_FILENO, F_GETFL, 0);          
    fcntl(STDIN_FILENO, F_SETFL, CORE.Input.Keyboard.defaultFileFlags | O_NONBLOCK); 

    
    int result = ioctl(STDIN_FILENO, KDGKBMODE, &CORE.Input.Keyboard.defaultMode);

    
    if (result < 0) TRACELOG(LOG_WARNING, "RPI: Failed to change keyboard mode, an SSH keyboard is probably used");
    else {
        
        
        
        
        
        ioctl(STDIN_FILENO, KDSKBMODE, K_XLATE);  
    }

    
    atexit(RestoreKeyboard);
}


static void RestoreKeyboard(void)
{
    
    tcsetattr(STDIN_FILENO, TCSANOW, &CORE.Input.Keyboard.defaultSettings);

    
    fcntl(STDIN_FILENO, F_SETFL, CORE.Input.Keyboard.defaultFileFlags);
    ioctl(STDIN_FILENO, KDSKBMODE, CORE.Input.Keyboard.defaultMode);
}



static void ProcessKeyboard(void)
{
    #define MAX_KEYBUFFER_SIZE      32      

    
    int bufferByteCount = 0;                        
    char keysBuffer[MAX_KEYBUFFER_SIZE] = { 0 };    

    
    bufferByteCount = read(STDIN_FILENO, keysBuffer, MAX_KEYBUFFER_SIZE);     

    
    for (int i = 0; i < MAX_KEYBOARD_KEYS; i++) CORE.Input.Keyboard.currentKeyState[i] = 0;

    
    for (int i = 0; i < bufferByteCount; i++)
    {
        
        
        if (keysBuffer[i] == 0x1b)
        {
            
            if (bufferByteCount == 1) CORE.Input.Keyboard.currentKeyState[CORE.Input.Keyboard.exitKey] = 1;
            else {
                if (keysBuffer[i + 1] == 0x5b)    
                {
                    if ((keysBuffer[i + 2] == 0x5b) || (keysBuffer[i + 2] == 0x31) || (keysBuffer[i + 2] == 0x32))
                    {
                        
                        switch (keysBuffer[i + 3])
                        {
                            case 0x41: CORE.Input.Keyboard.currentKeyState[290] = 1; break;    
                            case 0x42: CORE.Input.Keyboard.currentKeyState[291] = 1; break;    
                            case 0x43: CORE.Input.Keyboard.currentKeyState[292] = 1; break;    
                            case 0x44: CORE.Input.Keyboard.currentKeyState[293] = 1; break;    
                            case 0x45: CORE.Input.Keyboard.currentKeyState[294] = 1; break;    
                            case 0x37: CORE.Input.Keyboard.currentKeyState[295] = 1; break;    
                            case 0x38: CORE.Input.Keyboard.currentKeyState[296] = 1; break;    
                            case 0x39: CORE.Input.Keyboard.currentKeyState[297] = 1; break;    
                            case 0x30: CORE.Input.Keyboard.currentKeyState[298] = 1; break;    
                            case 0x31: CORE.Input.Keyboard.currentKeyState[299] = 1; break;    
                            case 0x33: CORE.Input.Keyboard.currentKeyState[300] = 1; break;    
                            case 0x34: CORE.Input.Keyboard.currentKeyState[301] = 1; break;    
                            default: break;
                        }

                        if (keysBuffer[i + 2] == 0x5b) i += 4;
                        else if ((keysBuffer[i + 2] == 0x31) || (keysBuffer[i + 2] == 0x32)) i += 5;
                    }
                    else {
                        switch (keysBuffer[i + 2])
                        {
                            case 0x41: CORE.Input.Keyboard.currentKeyState[265] = 1; break;    
                            case 0x42: CORE.Input.Keyboard.currentKeyState[264] = 1; break;    
                            case 0x43: CORE.Input.Keyboard.currentKeyState[262] = 1; break;    
                            case 0x44: CORE.Input.Keyboard.currentKeyState[263] = 1; break;    
                            default: break;
                        }

                        i += 3;  
                    }

                    
                }
            }
        }
        else if (keysBuffer[i] == 0x0a)     
        {
            CORE.Input.Keyboard.currentKeyState[257] = 1;

            CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount] = 257;     
            CORE.Input.Keyboard.keyPressedQueueCount++;
        }
        else if (keysBuffer[i] == 0x7f)     
        {
            CORE.Input.Keyboard.currentKeyState[259] = 1;

            CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount] = 257;     
            CORE.Input.Keyboard.keyPressedQueueCount++;
        }
        else {
            
            if ((keysBuffer[i] >= 97) && (keysBuffer[i] <= 122))
            {
                CORE.Input.Keyboard.currentKeyState[(int)keysBuffer[i] - 32] = 1;
            }
            else CORE.Input.Keyboard.currentKeyState[(int)keysBuffer[i]] = 1;

            CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount] = keysBuffer[i];     
            CORE.Input.Keyboard.keyPressedQueueCount++;
        }
    }

    
    if (CORE.Input.Keyboard.currentKeyState[CORE.Input.Keyboard.exitKey] == 1) CORE.Window.shouldClose = true;


    
    if (CORE.Input.Keyboard.currentKeyState[301] == 1)
    {
        TakeScreenshot(TextFormat("screenshot%03i.png", screenshotCounter));
        screenshotCounter++;
    }

}



static void InitEvdevInput(void)
{
    char path[MAX_FILEPATH_LENGTH] = { 0 };
    DIR *directory = NULL;
    struct dirent *entity = NULL;

    
    CORE.Input.Keyboard.fd = -1;

    
    for (int i = 0; i < MAX_TOUCH_POINTS; ++i)
    {
        CORE.Input.Touch.position[i].x = -1;
        CORE.Input.Touch.position[i].y = -1;
    }

    
    for (int i = 0; i < MAX_KEYBOARD_KEYS; i++) CORE.Input.Keyboard.currentKeyState[i] = 0;

    
    directory = opendir(DEFAULT_EVDEV_PATH);

    if (directory)
    {
        while ((entity = readdir(directory)) != NULL)
        {
            if ((strncmp("event", entity->d_name, strlen("event")) == 0) ||      (strncmp("mouse", entity->d_name, strlen("mouse")) == 0))
            {
                sprintf(path, "%s%s", DEFAULT_EVDEV_PATH, entity->d_name);
                ConfigureEvdevDevice(path);                                     
            }
        }

        closedir(directory);
    }
    else TRACELOG(LOG_WARNING, "RPI: Failed to open linux event directory: %s", DEFAULT_EVDEV_PATH);
}


static void ConfigureEvdevDevice(char *device)
{
    #define BITS_PER_LONG   (8*sizeof(long))
    #define NBITS(x)        ((((x) - 1)/BITS_PER_LONG) + 1)
    #define OFF(x)          ((x)%BITS_PER_LONG)
    #define BIT(x)          (1UL<<OFF(x))
    #define LONG(x)         ((x)/BITS_PER_LONG)
    #define TEST_BIT(array, bit) ((array[LONG(bit)] >> OFF(bit)) & 1)

    struct input_absinfo absinfo = { 0 };
    unsigned long evBits[NBITS(EV_MAX)] = { 0 };
    unsigned long absBits[NBITS(ABS_MAX)] = { 0 };
    unsigned long relBits[NBITS(REL_MAX)] = { 0 };
    unsigned long keyBits[NBITS(KEY_MAX)] = { 0 };
    bool hasAbs = false;
    bool hasRel = false;
    bool hasAbsMulti = false;
    int freeWorkerId = -1;
    int fd = -1;

    InputEventWorker *worker = NULL;

    
    
    
    for (int i = 0; i < sizeof(CORE.Input.eventWorker)/sizeof(InputEventWorker); ++i)
    {
        if (CORE.Input.eventWorker[i].threadId == 0)
        {
            freeWorkerId = i;
            break;
        }
    }

    
    if (freeWorkerId >= 0)
    {
        worker = &(CORE.Input.eventWorker[freeWorkerId]);       
        memset(worker, 0, sizeof(InputEventWorker));  
    }
    else {
        TRACELOG(LOG_WARNING, "RPI: Failed to create input device thread for %s, out of worker slots", device);
        return;
    }

    
    fd = open(device, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
    {
        TRACELOG(LOG_WARNING, "RPI: Failed to open input device: %s", device);
        return;
    }
    worker->fd = fd;

    
    int devNum = 0;
    char *ptrDevName = strrchr(device, 't');
    worker->eventNum = -1;

    if (ptrDevName != NULL)
    {
        if (sscanf(ptrDevName, "t%d", &devNum) == 1) worker->eventNum = devNum;
    }
    else worker->eventNum = 0;      

    
    
    

    
    
    ioctl(fd, EVIOCGBIT(0, sizeof(evBits)), evBits);    

    
    if (TEST_BIT(evBits, EV_ABS))
    {
        ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absBits)), absBits);

        
        if (TEST_BIT(absBits, ABS_X) && TEST_BIT(absBits, ABS_Y))
        {
            hasAbs = true;

            
            ioctl(fd, EVIOCGABS(ABS_X), &absinfo);
            worker->absRange.x = absinfo.minimum;
            worker->absRange.width = absinfo.maximum - absinfo.minimum;
            ioctl(fd, EVIOCGABS(ABS_Y), &absinfo);
            worker->absRange.y = absinfo.minimum;
            worker->absRange.height = absinfo.maximum - absinfo.minimum;
        }

        
        if (TEST_BIT(absBits, ABS_MT_POSITION_X) && TEST_BIT(absBits, ABS_MT_POSITION_Y))
        {
            hasAbsMulti = true;

            
            ioctl(fd, EVIOCGABS(ABS_X), &absinfo);
            worker->absRange.x = absinfo.minimum;
            worker->absRange.width = absinfo.maximum - absinfo.minimum;
            ioctl(fd, EVIOCGABS(ABS_Y), &absinfo);
            worker->absRange.y = absinfo.minimum;
            worker->absRange.height = absinfo.maximum - absinfo.minimum;
        }
    }

    
    if (TEST_BIT(evBits, EV_REL))
    {
        ioctl(fd, EVIOCGBIT(EV_REL, sizeof(relBits)), relBits);

        if (TEST_BIT(relBits, REL_X) && TEST_BIT(relBits, REL_Y)) hasRel = true;
    }

    
    if (TEST_BIT(evBits, EV_KEY))
    {
        ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keyBits)), keyBits);

        if (hasAbs || hasAbsMulti)
        {
            if (TEST_BIT(keyBits, BTN_TOUCH)) worker->isTouch = true;          
            if (TEST_BIT(keyBits, BTN_TOOL_FINGER)) worker->isTouch = true;    
            if (TEST_BIT(keyBits, BTN_TOOL_PEN)) worker->isTouch = true;       
            if (TEST_BIT(keyBits, BTN_STYLUS)) worker->isTouch = true;         
            if (worker->isTouch || hasAbsMulti) worker->isMultitouch = true;   
        }

        if (hasRel)
        {
            if (TEST_BIT(keyBits, BTN_LEFT)) worker->isMouse = true;           
            if (TEST_BIT(keyBits, BTN_RIGHT)) worker->isMouse = true;          
        }

        if (TEST_BIT(keyBits, BTN_A)) worker->isGamepad = true;                
        if (TEST_BIT(keyBits, BTN_TRIGGER)) worker->isGamepad = true;          
        if (TEST_BIT(keyBits, BTN_START)) worker->isGamepad = true;            
        if (TEST_BIT(keyBits, BTN_TL)) worker->isGamepad = true;               
        if (TEST_BIT(keyBits, BTN_TL)) worker->isGamepad = true;               

        if (TEST_BIT(keyBits, KEY_SPACE)) worker->isKeyboard = true;           
    }
    

    
    
    if (worker->isKeyboard && (CORE.Input.Keyboard.fd == -1))
    {
        
        
        
        TRACELOG(LOG_INFO, "RPI: Opening keyboard device: %s", device);
        CORE.Input.Keyboard.fd = worker->fd;
    }
    else if (worker->isTouch || worker->isMouse)
    {
        
        TRACELOG(LOG_INFO, "RPI: Opening input device: %s (%s%s%s%s)", device, worker->isMouse? "mouse " : "", worker->isMultitouch? "multitouch " : "", worker->isTouch? "touchscreen " : "", worker->isGamepad? "gamepad " : "");




        
        int error = pthread_create(&worker->threadId, NULL, &EventThread, (void *)worker);
        if (error != 0)
        {
            TRACELOG(LOG_WARNING, "RPI: Failed to create input device thread: %s (error: %d)", device, error);
            worker->threadId = 0;
            close(fd);
        }


        
        int maxTouchNumber = -1;

        for (int i = 0; i < sizeof(CORE.Input.eventWorker)/sizeof(InputEventWorker); ++i)
        {
            if (CORE.Input.eventWorker[i].isTouch && (CORE.Input.eventWorker[i].eventNum > maxTouchNumber)) maxTouchNumber = CORE.Input.eventWorker[i].eventNum;
        }

        
        for (int i = 0; i < sizeof(CORE.Input.eventWorker)/sizeof(InputEventWorker); ++i)
        {
            if (CORE.Input.eventWorker[i].isTouch && (CORE.Input.eventWorker[i].eventNum < maxTouchNumber))
            {
                if (CORE.Input.eventWorker[i].threadId != 0)
                {
                    TRACELOG(LOG_WARNING, "RPI: Found duplicate touchscreen, killing touchscreen on event: %d", i);
                    pthread_cancel(CORE.Input.eventWorker[i].threadId);
                    close(CORE.Input.eventWorker[i].fd);
                }
            }
        }

    }
    else close(fd);  
    
}

static void PollKeyboardEvents(void)
{
    
    
    
    static const int keymapUS[] = {
        0, 256, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 45, 61, 259, 258, 81, 87, 69, 82, 84, 89, 85, 73, 79, 80, 91, 93, 257, 341, 65, 83, 68, 70, 71, 72, 74, 75, 76, 59, 39, 96, 340, 92, 90, 88, 67, 86, 66, 78, 77, 44, 46, 47, 344, 332, 342, 32, 280, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 282, 281, 327, 328, 329, 333, 324, 325, 326, 334, 321, 322, 323, 320, 330, 0, 85, 86, 300, 301, 89, 90, 91, 92, 93, 94, 95, 335, 345, 331, 283, 346, 101, 268, 265, 266, 263, 262, 269, 264, 267, 260, 261, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 347, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 0, 0, 0, 0, 0, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 0, 0, 0, 0, 0, 0, 0 };















    int fd = CORE.Input.Keyboard.fd;
    if (fd == -1) return;

    struct input_event event = { 0 };
    int keycode = -1;

    
    while (read(fd, &event, sizeof(event)) == (int)sizeof(event))
    {
        
        if (event.type == EV_KEY)
        {

            
            CORE.Input.Keyboard.evtMode = true;

            
            if ((event.code >= 1) && (event.code <= 255))     
            {
                keycode = keymapUS[event.code & 0xFF];     

                
                if ((keycode > 0) && (keycode < sizeof(CORE.Input.Keyboard.currentKeyState)))
                {
                    
                    
                    
                    CORE.Input.Keyboard.currentKeyState[keycode] = (event.value >= 1)? 1 : 0;
                    if (event.value >= 1)
                    {
                        CORE.Input.Keyboard.keyPressedQueue[CORE.Input.Keyboard.keyPressedQueueCount] = keycode;     
                        CORE.Input.Keyboard.keyPressedQueueCount++;
                    }

                #if defined(SUPPORT_SCREEN_CAPTURE)
                    
                    if (CORE.Input.Keyboard.currentKeyState[301] == 1)
                    {
                        TakeScreenshot(TextFormat("screenshot%03i.png", screenshotCounter));
                        screenshotCounter++;
                    }
                #endif

                    if (CORE.Input.Keyboard.currentKeyState[CORE.Input.Keyboard.exitKey] == 1) CORE.Window.shouldClose = true;

                    TRACELOGD("RPI: KEY_%s ScanCode: %4i KeyCode: %4i", event.value == 0 ? "UP":"DOWN", event.code, keycode);
                }
            }
        }
    }
}


static void *EventThread(void *arg)
{
    struct input_event event = { 0 };
    InputEventWorker *worker = (InputEventWorker *)arg;

    int touchAction = -1;           
    bool gestureUpdate = false;     

    while (!CORE.Window.shouldClose)
    {
        
        while (read(worker->fd, &event, sizeof(event)) == (int)sizeof(event))
        {
            
            if (event.type == EV_REL)
            {
                if (event.code == REL_X)
                {
                    CORE.Input.Mouse.currentPosition.x += event.value;
                    CORE.Input.Touch.position[0].x = CORE.Input.Mouse.currentPosition.x;

                    touchAction = 2;    
                    gestureUpdate = true;
                }

                if (event.code == REL_Y)
                {
                    CORE.Input.Mouse.currentPosition.y += event.value;
                    CORE.Input.Touch.position[0].y = CORE.Input.Mouse.currentPosition.y;

                    touchAction = 2;    
                    gestureUpdate = true;
                }

                if (event.code == REL_WHEEL) CORE.Input.Mouse.currentWheelMove.y += event.value;
            }

            
            if (event.type == EV_ABS)
            {
                
                if (event.code == ABS_X)
                {
                    CORE.Input.Mouse.currentPosition.x = (event.value - worker->absRange.x)*CORE.Window.screen.width/worker->absRange.width;    
                    CORE.Input.Touch.position[0].x = (event.value - worker->absRange.x)*CORE.Window.screen.width/worker->absRange.width;        

                    touchAction = 2;    
                    gestureUpdate = true;
                }

                if (event.code == ABS_Y)
                {
                    CORE.Input.Mouse.currentPosition.y = (event.value - worker->absRange.y)*CORE.Window.screen.height/worker->absRange.height;  
                    CORE.Input.Touch.position[0].y = (event.value - worker->absRange.y)*CORE.Window.screen.height/worker->absRange.height;      

                    touchAction = 2;    
                    gestureUpdate = true;
                }

                
                if (event.code == ABS_MT_SLOT) worker->touchSlot = event.value;   

                if (event.code == ABS_MT_POSITION_X)
                {
                    if (worker->touchSlot < MAX_TOUCH_POINTS) CORE.Input.Touch.position[worker->touchSlot].x = (event.value - worker->absRange.x)*CORE.Window.screen.width/worker->absRange.width;    
                }

                if (event.code == ABS_MT_POSITION_Y)
                {
                    if (worker->touchSlot < MAX_TOUCH_POINTS) CORE.Input.Touch.position[worker->touchSlot].y = (event.value - worker->absRange.y)*CORE.Window.screen.height/worker->absRange.height;  
                }

                if (event.code == ABS_MT_TRACKING_ID)
                {
                    if ((event.value < 0) && (worker->touchSlot < MAX_TOUCH_POINTS))
                    {
                        
                        CORE.Input.Touch.position[worker->touchSlot].x = -1;
                        CORE.Input.Touch.position[worker->touchSlot].y = -1;
                    }
                }

                
                if (event.code == ABS_PRESSURE)
                {
                    int previousMouseLeftButtonState = CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_LEFT];

                    if (!event.value && previousMouseLeftButtonState)
                    {
                        CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_LEFT] = 0;

                        touchAction = 0;    
                        gestureUpdate = true;
                    }

                    if (event.value && !previousMouseLeftButtonState)
                    {
                        CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_LEFT] = 1;

                        touchAction = 1;    
                        gestureUpdate = true;
                    }
                }

            }

            
            if (event.type == EV_KEY)
            {
                
                if ((event.code == BTN_TOUCH) || (event.code == BTN_LEFT))
                {
                    CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_LEFT] = event.value;

                    if (event.value > 0) touchAction = 1;   
                    else touchAction = 0;       
                    gestureUpdate = true;
                }

                if (event.code == BTN_RIGHT) CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_RIGHT] = event.value;
                if (event.code == BTN_MIDDLE) CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_MIDDLE] = event.value;
                if (event.code == BTN_SIDE) CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_SIDE] = event.value;
                if (event.code == BTN_EXTRA) CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_EXTRA] = event.value;
                if (event.code == BTN_FORWARD) CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_FORWARD] = event.value;
                if (event.code == BTN_BACK) CORE.Input.Mouse.currentButtonStateEvdev[MOUSE_BUTTON_BACK] = event.value;
            }

            
            if (!CORE.Input.Mouse.cursorHidden)
            {
                if (CORE.Input.Mouse.currentPosition.x < 0) CORE.Input.Mouse.currentPosition.x = 0;
                if (CORE.Input.Mouse.currentPosition.x > CORE.Window.screen.width/CORE.Input.Mouse.scale.x) CORE.Input.Mouse.currentPosition.x = CORE.Window.screen.width/CORE.Input.Mouse.scale.x;

                if (CORE.Input.Mouse.currentPosition.y < 0) CORE.Input.Mouse.currentPosition.y = 0;
                if (CORE.Input.Mouse.currentPosition.y > CORE.Window.screen.height/CORE.Input.Mouse.scale.y) CORE.Input.Mouse.currentPosition.y = CORE.Window.screen.height/CORE.Input.Mouse.scale.y;
            }


            if (gestureUpdate)
            {
                GestureEvent gestureEvent = { 0 };

                gestureEvent.pointCount = 0;
                gestureEvent.touchAction = touchAction;

                if (CORE.Input.Touch.position[0].x >= 0) gestureEvent.pointCount++;
                if (CORE.Input.Touch.position[1].x >= 0) gestureEvent.pointCount++;
                if (CORE.Input.Touch.position[2].x >= 0) gestureEvent.pointCount++;
                if (CORE.Input.Touch.position[3].x >= 0) gestureEvent.pointCount++;

                gestureEvent.pointId[0] = 0;
                gestureEvent.pointId[1] = 1;
                gestureEvent.pointId[2] = 2;
                gestureEvent.pointId[3] = 3;

                gestureEvent.position[0] = CORE.Input.Touch.position[0];
                gestureEvent.position[1] = CORE.Input.Touch.position[1];
                gestureEvent.position[2] = CORE.Input.Touch.position[2];
                gestureEvent.position[3] = CORE.Input.Touch.position[3];

                ProcessGestureEvent(gestureEvent);
            }

        }

        WaitTime(0.005);    
    }

    close(worker->fd);

    return NULL;
}


static void InitGamepad(void)
{
    char gamepadDev[128] = { 0 };

    for (int i = 0; i < MAX_GAMEPADS; i++)
    {
        sprintf(gamepadDev, "%s%i", DEFAULT_GAMEPAD_DEV, i);

        if ((CORE.Input.Gamepad.streamId[i] = open(gamepadDev, O_RDONLY | O_NONBLOCK)) < 0)
        {
            
            if (i == 0) TRACELOG(LOG_WARNING, "RPI: Failed to open Gamepad device, no gamepad available");
        }
        else {
            CORE.Input.Gamepad.ready[i] = true;

            
            if (i == 0)
            {
                int error = pthread_create(&CORE.Input.Gamepad.threadId, NULL, &GamepadThread, NULL);

                if (error != 0) TRACELOG(LOG_WARNING, "RPI: Failed to create gamepad input event thread");
                else  TRACELOG(LOG_INFO, "RPI: Gamepad device initialized successfully");
            }
        }
    }
}


static void *GamepadThread(void *arg)
{
    #define JS_EVENT_BUTTON         0x01    
    #define JS_EVENT_AXIS           0x02    
    #define JS_EVENT_INIT           0x80    

    struct js_event {
        unsigned int time;      
        short value;            
        unsigned char type;     
        unsigned char number;   
    };

    
    struct js_event gamepadEvent = { 0 };

    while (!CORE.Window.shouldClose)
    {
        for (int i = 0; i < MAX_GAMEPADS; i++)
        {
            if (read(CORE.Input.Gamepad.streamId[i], &gamepadEvent, sizeof(struct js_event)) == (int)sizeof(struct js_event))
            {
                gamepadEvent.type &= ~JS_EVENT_INIT;     

                
                if (gamepadEvent.type == JS_EVENT_BUTTON)
                {
                    

                    if (gamepadEvent.number < MAX_GAMEPAD_BUTTONS)
                    {
                        
                        CORE.Input.Gamepad.currentButtonState[i][gamepadEvent.number] = (int)gamepadEvent.value;

                        if ((int)gamepadEvent.value == 1) CORE.Input.Gamepad.lastButtonPressed = gamepadEvent.number;
                        else CORE.Input.Gamepad.lastButtonPressed = 0;       
                    }
                }
                else if (gamepadEvent.type == JS_EVENT_AXIS)
                {
                    

                    if (gamepadEvent.number < MAX_GAMEPAD_AXIS)
                    {
                        
                        CORE.Input.Gamepad.axisState[i][gamepadEvent.number] = (float)gamepadEvent.value/32768;
                    }
                }
            }
            else WaitTime(0.001);    
        }
    }

    return NULL;
}




static int FindMatchingConnectorMode(const drmModeConnector *connector, const drmModeModeInfo *mode)
{
    if (NULL == connector) return -1;
    if (NULL == mode) return -1;

    
    #define BINCMP(a, b) memcmp((a), (b), (sizeof(a) < sizeof(b)) ? sizeof(a) : sizeof(b))

    for (size_t i = 0; i < connector->count_modes; i++)
    {
        TRACELOG(LOG_TRACE, "DISPLAY: DRM mode: %d %ux%u@%u %s", i, connector->modes[i].hdisplay, connector->modes[i].vdisplay, connector->modes[i].vrefresh, (connector->modes[i].flags & DRM_MODE_FLAG_INTERLACE) ? "interlaced" : "progressive");

        if (0 == BINCMP(&CORE.Window.crtc->mode, &CORE.Window.connector->modes[i])) return i;
    }

    return -1;

    #undef BINCMP
}


static int FindExactConnectorMode(const drmModeConnector *connector, uint width, uint height, uint fps, bool allowInterlaced)
{
    TRACELOG(LOG_TRACE, "DISPLAY: Searching exact connector mode for %ux%u@%u, selecting an interlaced mode is allowed: %s", width, height, fps, allowInterlaced ? "yes" : "no");

    if (NULL == connector) return -1;

    for (int i = 0; i < CORE.Window.connector->count_modes; i++)
    {
        const drmModeModeInfo *const mode = &CORE.Window.connector->modes[i];

        TRACELOG(LOG_TRACE, "DISPLAY: DRM Mode %d %ux%u@%u %s", i, mode->hdisplay, mode->vdisplay, mode->vrefresh, (mode->flags & DRM_MODE_FLAG_INTERLACE) ? "interlaced" : "progressive");

        if ((mode->flags & DRM_MODE_FLAG_INTERLACE) && (!allowInterlaced)) continue;

        if ((mode->hdisplay == width) && (mode->vdisplay == height) && (mode->vrefresh == fps)) return i;
    }

    TRACELOG(LOG_TRACE, "DISPLAY: No DRM exact matching mode found");
    return -1;
}


static int FindNearestConnectorMode(const drmModeConnector *connector, uint width, uint height, uint fps, bool allowInterlaced)
{
    TRACELOG(LOG_TRACE, "DISPLAY: Searching nearest connector mode for %ux%u@%u, selecting an interlaced mode is allowed: %s", width, height, fps, allowInterlaced ? "yes" : "no");

    if (NULL == connector) return -1;

    int nearestIndex = -1;
    for (int i = 0; i < CORE.Window.connector->count_modes; i++)
    {
        const drmModeModeInfo *const mode = &CORE.Window.connector->modes[i];

        TRACELOG(LOG_TRACE, "DISPLAY: DRM mode: %d %ux%u@%u %s", i, mode->hdisplay, mode->vdisplay, mode->vrefresh, (mode->flags & DRM_MODE_FLAG_INTERLACE) ? "interlaced" : "progressive");

        if ((mode->hdisplay < width) || (mode->vdisplay < height))
        {
            TRACELOG(LOG_TRACE, "DISPLAY: DRM mode is too small");
            continue;
        }

        if ((mode->flags & DRM_MODE_FLAG_INTERLACE) && (!allowInterlaced))
        {
            TRACELOG(LOG_TRACE, "DISPLAY: DRM shouldn't choose an interlaced mode");
            continue;
        }

        if (nearestIndex < 0)
        {
            nearestIndex = i;
            continue;
        }

        const int widthDiff = abs(mode->hdisplay - width);
        const int heightDiff = abs(mode->vdisplay - height);
        const int fpsDiff = abs(mode->vrefresh - fps);

        const int nearestWidthDiff = abs(CORE.Window.connector->modes[nearestIndex].hdisplay - width);
        const int nearestHeightDiff = abs(CORE.Window.connector->modes[nearestIndex].vdisplay - height);
        const int nearestFpsDiff = abs(CORE.Window.connector->modes[nearestIndex].vrefresh - fps);

        if ((widthDiff < nearestWidthDiff) || (heightDiff < nearestHeightDiff) || (fpsDiff < nearestFpsDiff)) {
            nearestIndex = i;
        }
    }

    return nearestIndex;
}





static void LoadAutomationEvents(const char *fileName)
{
    

    
    

    
    FILE *repFile = fopen(fileName, "rt");

    if (repFile != NULL)
    {
        unsigned int count = 0;
        char buffer[256] = { 0 };

        fgets(buffer, 256, repFile);

        while (!feof(repFile))
        {
            if (buffer[0] == 'c') sscanf(buffer, "c %i", &eventCount);
            else if (buffer[0] == 'e')
            {
                sscanf(buffer, "e %d %d %d %d %d", &events[count].frame, &events[count].type, &events[count].params[0], &events[count].params[1], &events[count].params[2]);

                count++;
            }

            fgets(buffer, 256, repFile);
        }

        if (count != eventCount) TRACELOG(LOG_WARNING, "Events count provided is different than count");

        fclose(repFile);
    }

    TRACELOG(LOG_WARNING, "Events loaded: %i", eventCount);
}


static void ExportAutomationEvents(const char *fileName)
{
    unsigned char fileId[4] = "rEP ";

    
    

    
    FILE *repFile = fopen(fileName, "wt");

    if (repFile != NULL)
    {
        fprintf(repFile, "# Automation events list\n");
        fprintf(repFile, "#    c <events_count>\n");
        fprintf(repFile, "#    e <frame> <event_type> <param0> <param1> <param2> // <event_type_name>\n");

        fprintf(repFile, "c %i\n", eventCount);
        for (int i = 0; i < eventCount; i++)
        {
            fprintf(repFile, "e %i %i %i %i %i // %s\n", events[i].frame, events[i].type, events[i].params[0], events[i].params[1], events[i].params[2], autoEventTypeName[events[i].type]);
        }

        fclose(repFile);
    }
}



static void RecordAutomationEvent(unsigned int frame)
{
    for (int key = 0; key < MAX_KEYBOARD_KEYS; key++)
    {
        
        if (CORE.Input.Keyboard.previousKeyState[key] && !CORE.Input.Keyboard.currentKeyState[key])
        {
            events[eventCount].frame = frame;
            events[eventCount].type = INPUT_KEY_UP;
            events[eventCount].params[0] = key;
            events[eventCount].params[1] = 0;
            events[eventCount].params[2] = 0;

            TRACELOG(LOG_INFO, "[%i] INPUT_KEY_UP: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
            eventCount++;
        }

        
        if (CORE.Input.Keyboard.currentKeyState[key])
        {
            events[eventCount].frame = frame;
            events[eventCount].type = INPUT_KEY_DOWN;
            events[eventCount].params[0] = key;
            events[eventCount].params[1] = 0;
            events[eventCount].params[2] = 0;

            TRACELOG(LOG_INFO, "[%i] INPUT_KEY_DOWN: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
            eventCount++;
        }
    }

    for (int button = 0; button < MAX_MOUSE_BUTTONS; button++)
    {
        
        if (CORE.Input.Mouse.previousButtonState[button] && !CORE.Input.Mouse.currentButtonState[button])
        {
            events[eventCount].frame = frame;
            events[eventCount].type = INPUT_MOUSE_BUTTON_UP;
            events[eventCount].params[0] = button;
            events[eventCount].params[1] = 0;
            events[eventCount].params[2] = 0;

            TRACELOG(LOG_INFO, "[%i] INPUT_MOUSE_BUTTON_UP: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
            eventCount++;
        }

        
        if (CORE.Input.Mouse.currentButtonState[button])
        {
            events[eventCount].frame = frame;
            events[eventCount].type = INPUT_MOUSE_BUTTON_DOWN;
            events[eventCount].params[0] = button;
            events[eventCount].params[1] = 0;
            events[eventCount].params[2] = 0;

            TRACELOG(LOG_INFO, "[%i] INPUT_MOUSE_BUTTON_DOWN: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
            eventCount++;
        }
    }

    
    if (((int)CORE.Input.Mouse.currentPosition.x != (int)CORE.Input.Mouse.previousPosition.x) || ((int)CORE.Input.Mouse.currentPosition.y != (int)CORE.Input.Mouse.previousPosition.y))
    {
        events[eventCount].frame = frame;
        events[eventCount].type = INPUT_MOUSE_POSITION;
        events[eventCount].params[0] = (int)CORE.Input.Mouse.currentPosition.x;
        events[eventCount].params[1] = (int)CORE.Input.Mouse.currentPosition.y;
        events[eventCount].params[2] = 0;

        TRACELOG(LOG_INFO, "[%i] INPUT_MOUSE_POSITION: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
        eventCount++;
    }

    
    if (((int)CORE.Input.Mouse.currentWheelMove.x != (int)CORE.Input.Mouse.previousWheelMove.x) || ((int)CORE.Input.Mouse.currentWheelMove.y != (int)CORE.Input.Mouse.previousWheelMove.y))
    {
        events[eventCount].frame = frame;
        events[eventCount].type = INPUT_MOUSE_WHEEL_MOTION;
        events[eventCount].params[0] = (int)CORE.Input.Mouse.currentWheelMove.x;
        events[eventCount].params[1] = (int)CORE.Input.Mouse.currentWheelMove.y;;
        events[eventCount].params[2] = 0;

        TRACELOG(LOG_INFO, "[%i] INPUT_MOUSE_WHEEL_MOTION: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
        eventCount++;
    }

    for (int id = 0; id < MAX_TOUCH_POINTS; id++)
    {
        
        if (CORE.Input.Touch.previousTouchState[id] && !CORE.Input.Touch.currentTouchState[id])
        {
            events[eventCount].frame = frame;
            events[eventCount].type = INPUT_TOUCH_UP;
            events[eventCount].params[0] = id;
            events[eventCount].params[1] = 0;
            events[eventCount].params[2] = 0;

            TRACELOG(LOG_INFO, "[%i] INPUT_TOUCH_UP: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
            eventCount++;
        }

        
        if (CORE.Input.Touch.currentTouchState[id])
        {
            events[eventCount].frame = frame;
            events[eventCount].type = INPUT_TOUCH_DOWN;
            events[eventCount].params[0] = id;
            events[eventCount].params[1] = 0;
            events[eventCount].params[2] = 0;

            TRACELOG(LOG_INFO, "[%i] INPUT_TOUCH_DOWN: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
            eventCount++;
        }

        
        
        
    }

    for (int gamepad = 0; gamepad < MAX_GAMEPADS; gamepad++)
    {
        
        

        
        

        for (int button = 0; button < MAX_GAMEPAD_BUTTONS; button++)
        {
            
            if (CORE.Input.Gamepad.previousButtonState[gamepad][button] && !CORE.Input.Gamepad.currentButtonState[gamepad][button])
            {
                events[eventCount].frame = frame;
                events[eventCount].type = INPUT_GAMEPAD_BUTTON_UP;
                events[eventCount].params[0] = gamepad;
                events[eventCount].params[1] = button;
                events[eventCount].params[2] = 0;

                TRACELOG(LOG_INFO, "[%i] INPUT_GAMEPAD_BUTTON_UP: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
                eventCount++;
            }

            
            if (CORE.Input.Gamepad.currentButtonState[gamepad][button])
            {
                events[eventCount].frame = frame;
                events[eventCount].type = INPUT_GAMEPAD_BUTTON_DOWN;
                events[eventCount].params[0] = gamepad;
                events[eventCount].params[1] = button;
                events[eventCount].params[2] = 0;

                TRACELOG(LOG_INFO, "[%i] INPUT_GAMEPAD_BUTTON_DOWN: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
                eventCount++;
            }
        }

        for (int axis = 0; axis < MAX_GAMEPAD_AXIS; axis++)
        {
            
            if (CORE.Input.Gamepad.axisState[gamepad][axis] > 0.1f)
            {
                events[eventCount].frame = frame;
                events[eventCount].type = INPUT_GAMEPAD_AXIS_MOTION;
                events[eventCount].params[0] = gamepad;
                events[eventCount].params[1] = axis;
                events[eventCount].params[2] = (int)(CORE.Input.Gamepad.axisState[gamepad][axis]*32768.0f);

                TRACELOG(LOG_INFO, "[%i] INPUT_GAMEPAD_AXIS_MOTION: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
                eventCount++;
            }
        }
    }

    
    if (GESTURES.current != GESTURE_NONE)
    {
        events[eventCount].frame = frame;
        events[eventCount].type = INPUT_GESTURE;
        events[eventCount].params[0] = GESTURES.current;
        events[eventCount].params[1] = 0;
        events[eventCount].params[2] = 0;

        TRACELOG(LOG_INFO, "[%i] INPUT_GESTURE: %i, %i, %i", events[eventCount].frame, events[eventCount].params[0], events[eventCount].params[1], events[eventCount].params[2]);
        eventCount++;
    }
}


static void PlayAutomationEvent(unsigned int frame)
{
    for (unsigned int i = 0; i < eventCount; i++)
    {
        if (events[i].frame == frame)
        {
            switch (events[i].type)
            {
                
                case INPUT_KEY_UP: CORE.Input.Keyboard.currentKeyState[events[i].params[0]] = false; break;             
                case INPUT_KEY_DOWN: CORE.Input.Keyboard.currentKeyState[events[i].params[0]] = true; break;            
                case INPUT_MOUSE_BUTTON_UP: CORE.Input.Mouse.currentButtonState[events[i].params[0]] = false; break;    
                case INPUT_MOUSE_BUTTON_DOWN: CORE.Input.Mouse.currentButtonState[events[i].params[0]] = true; break;   
                case INPUT_MOUSE_POSITION:      
                {
                    CORE.Input.Mouse.currentPosition.x = (float)events[i].params[0];
                    CORE.Input.Mouse.currentPosition.y = (float)events[i].params[1];
                } break;
                case INPUT_MOUSE_WHEEL_MOTION:  
                {
                    CORE.Input.Mouse.currentWheelMove.x = (float)events[i].params[0]; break;
                    CORE.Input.Mouse.currentWheelMove.y = (float)events[i].params[1]; break;
                } break;
                case INPUT_TOUCH_UP: CORE.Input.Touch.currentTouchState[events[i].params[0]] = false; break;            
                case INPUT_TOUCH_DOWN: CORE.Input.Touch.currentTouchState[events[i].params[0]] = true; break;           
                case INPUT_TOUCH_POSITION:      
                {
                    CORE.Input.Touch.position[events[i].params[0]].x = (float)events[i].params[1];
                    CORE.Input.Touch.position[events[i].params[0]].y = (float)events[i].params[2];
                } break;
                case INPUT_GAMEPAD_CONNECT: CORE.Input.Gamepad.ready[events[i].params[0]] = true; break;                
                case INPUT_GAMEPAD_DISCONNECT: CORE.Input.Gamepad.ready[events[i].params[0]] = false; break;            
                case INPUT_GAMEPAD_BUTTON_UP: CORE.Input.Gamepad.currentButtonState[events[i].params[0]][events[i].params[1]] = false; break;    
                case INPUT_GAMEPAD_BUTTON_DOWN: CORE.Input.Gamepad.currentButtonState[events[i].params[0]][events[i].params[1]] = true; break;   
                case INPUT_GAMEPAD_AXIS_MOTION: 
                {
                    CORE.Input.Gamepad.axisState[events[i].params[0]][events[i].params[1]] = ((float)events[i].params[2]/32768.0f);
                } break;
                case INPUT_GESTURE: GESTURES.current = events[i].params[0]; break;     

                
                case WINDOW_CLOSE: CORE.Window.shouldClose = true; break;
                case WINDOW_MAXIMIZE: MaximizeWindow(); break;
                case WINDOW_MINIMIZE: MinimizeWindow(); break;
                case WINDOW_RESIZE: SetWindowSize(events[i].params[0], events[i].params[1]); break;

                
                case ACTION_TAKE_SCREENSHOT:
                {
                    TakeScreenshot(TextFormat("screenshot%03i.png", screenshotCounter));
                    screenshotCounter++;
                } break;
                case ACTION_SETTARGETFPS: SetTargetFPS(events[i].params[0]); break;
                default: break;
            }
        }
    }
}





const char *TextFormat(const char *text, ...)
{

    #define MAX_TEXTFORMAT_BUFFERS      4        


    #define MAX_TEXT_BUFFER_LENGTH   1024        


    
    static char buffers[MAX_TEXTFORMAT_BUFFERS][MAX_TEXT_BUFFER_LENGTH] = { 0 };
    static int index = 0;

    char *currentBuffer = buffers[index];
    memset(currentBuffer, 0, MAX_TEXT_BUFFER_LENGTH);   

    va_list args;
    va_start(args, text);
    vsnprintf(currentBuffer, MAX_TEXT_BUFFER_LENGTH, text, args);
    va_end(args);

    index += 1;     
    if (index >= MAX_TEXTFORMAT_BUFFERS) index = 0;

    return currentBuffer;
}

