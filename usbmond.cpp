
#define LOG_TAG "Usbmond"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <cutils/log.h>
#include <cutils/uevent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <cutils/klog.h>
#include <cutils/properties.h>
#include <linux/netlink.h>

#if 0
#define USBMON_ERR(x...)     KLOG_ERROR("usbmond", x)
#define USBMON_NOTICE(x...)  KLOG_NOTICE("usbmond", x)
#define USBMON_INFO(x...)    KLOG_INFO("usbmond", x)
#define USBMON_DBG(x...)     KLOG_DEBUG("usbmond", x)
#endif

#define USBMON_ERR(x...)    android_printLog(ANDROID_LOG_ERROR,"usbmond",x)
#define USBMON_DBG(x...)    android_printLog(ANDROID_LOG_DEBUG,"usbmond",x)

#define SOCKET_BUF_SIZE  (64*1024)
#define UEVENT_MSG_LEN  1024

#define ANDROID_USB_PATH  "/sys/class/android_usb/android0"
#define MASS_STORAGE_INQUIRY_STRING_PATH  "/sys/class/android_usb/android0/f_mass_storage/inquiry_string"
#define RNDIS_PATH  "/sys/class/android_usb/f_rndis"
#define MONITOR_PATH  "/sys/monitor/usb_port/config/run"
#define USB_SERIALNUM_PATH  "/data/usb_serialnumber"
#define ANDROID_USB_ENABLE_PATH  "/sys/class/android_usb/android0/enable"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#define USB_MODESWITCH_RETRY_COUNT    5

static char save_buffer[4096];
static char inquiry_string[32];

static const char *android_item[] = {
    "idProduct",
    "idVendor",
    "bDeviceClass",
    "bDeviceProtocol",
    "bDeviceSubClass",
    "bcdDevice",

    "iManufacturer",
    "iProduct",
    "iSerial",

    "functions",
    "enable"
};

static const char *rndis_item[] = {
    "manufacturer",
    "vendorID",
    "wceis"
};

static const char *extern_item[] = {
    "uMa",
    "uPr",
    "uSe",
    "sMo",
    "sVe",
    "sRe",
};

struct uevent {
    const char *action;
    const char *path;
    const char *subsystem;
    const char *switch_state;
    const char *devtype;	//DEVTYPE=
    const char *usb_state;	//USB_STATE=DISCONNECTED, CONNECTED
};

struct usbmon_stats_t {
    unsigned int b_in;			//USB_B_IN, USB_B_OUT
    unsigned int g_android_con;		//USB_STATE=DISCONNECTED, CONNECTED
    unsigned int b_in_cnt;		// if b out sent, but disconnect event not recieved, cnt++
    unsigned int a_in;			//USB_A_IN, USB_A_OUT
    unsigned int usb_dev_con;		//DEVTYPE=usb_device, add or remove
    unsigned int usb_dev_cnt;		// usb device count.
    unsigned int gadget_installed;
    unsigned int uhost_installed;
    unsigned int install_envent_pend;
};

static struct usbmon_stats_t usbmon_stats;


static void hex_to_char(const char *source_hex, char *dst_char, unsigned char length)
{
    unsigned char i = 0, temp;   
    
    while(i < length) {
      temp = (source_hex[i] >> 4 ) & 0x0f;
      if(temp > 9)
          temp = temp - 10+ 'A';
      else
          temp = temp + '0';
      dst_char[i*2]= temp;

      temp = source_hex[i]& 0x0f;
      if(temp > 9)
          temp = temp - 10 + 'A';
      else
          temp = temp + '0';
      dst_char[i*2 + 1]= temp;
      i = i + 1;
    }
}

static int create_usbserialnumber(const char *filename)
{  
    char serialnumber_hex[16], serialnumber_char[32];
    int fd, length;
    
    fd =open("/dev/random", O_RDONLY);
    if(fd < 0) {
      printf("open random file fail\n");
      return -1;
    }
    length =read(fd, serialnumber_hex, sizeof(serialnumber_hex));
    printf("get serialnumber_hex length %d actually\n", length);
    close(fd);
    
    hex_to_char(serialnumber_hex, serialnumber_char, sizeof(serialnumber_hex));
        
    fd =open(filename, O_CREAT | O_WRONLY, 777);
    if(fd < 0) {
      printf("open and build %s fail\n", filename);
      return -1;
    }
    length = write(fd, serialnumber_char, sizeof(serialnumber_char));
    printf("save serialnumber_char length %d actually\n", length);
    close(fd);
    
    return 0;
}


static int file_is_exist(const char *filename)
{
  int fd;
  
  fd =open(filename, O_RDONLY);
  if(fd < 0)
    return -1;
  close(fd);
  
  return 0;  
}

/*
 * ACTION=change
 * DEVPATH=/devices/virtual/android_usb/android0
 * SUBSYSTEM=android_usb
 * USB_STATE=DISCONNECTED
*/
static void process_usb_uevent(struct uevent *uevent)
{
    printf("android usb event { '%s', '%s', '%s', '%s' }\n", uevent->action, uevent->path, 
                    uevent->subsystem, uevent->usb_state);

    if (!strcmp(uevent->usb_state, "CONNECTED")) {
        usbmon_stats.g_android_con = 1;
        usbmon_stats.install_envent_pend = 1;
    } else if (!strcmp(uevent->usb_state, "DISCONNECTED")) {
        usbmon_stats.g_android_con = 0;
        usbmon_stats.install_envent_pend = 1;
    }
 
    return;
}


static void android_state_save(void)
{
    unsigned int i;
    int fd,length;
    char path[255];
    char *ptr = save_buffer;
    memset(save_buffer, 0, sizeof(save_buffer)); 
    
    for(i = 0;i < ARRAY_SIZE(rndis_item);i++) {
        //memset(path, 0, sizeof(path)); 
        sprintf(path, "%s/%s", RNDIS_PATH, rndis_item[i]);
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            USBMON_ERR("rndis_item: open  %s error\n",path);
        } else {
            length = read(fd, ptr, sizeof(save_buffer));
            USBMON_DBG("read %s :%s %d\n", path, ptr, length);
            ptr += length - 1;
            if(*ptr != '\n')
              ptr++;
            *ptr = '\0';    
            ptr++;
            close(fd);
        } 
    }
        
    for(i = 0;i < ARRAY_SIZE(android_item);i++){
        //memset(path, 0, sizeof(path)); 
        sprintf(path, "%s/%s", ANDROID_USB_PATH, android_item[i]);
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            USBMON_ERR("android_item: open  %s error\n",path);
        } else {
            length = read(fd, ptr, sizeof(save_buffer));
            USBMON_DBG("read %s :%s %d\n", path, ptr, length);
            ptr += length - 1;
            if(*ptr != '\n')
              ptr++;
            *ptr = '\0';
            ptr++;
            close(fd);
        }  
    }
}

static void android_state_restore(void)
{
    unsigned int i;
    int fd,length;
    char path[255];
    char *ptr = save_buffer;
    
    for(i = 0;i < ARRAY_SIZE(rndis_item);i++){
        //memset(path, 0, sizeof(path)); 
        sprintf(path, "%s/%s", RNDIS_PATH, rndis_item[i]);
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            USBMON_ERR("rndis_item: open  %s error\n",path);
        } else {
            USBMON_DBG("string is %s\n", ptr);
            length = write(fd, ptr, strlen(ptr));
            USBMON_DBG("length is %d\n", length);
            while(*ptr != '\0')
              ptr++;
            ptr++;
            close(fd);
        }  
    } 

    for(i = 0;i < ARRAY_SIZE(android_item) - 1;i++){
        //memset(path, 0, sizeof(path)); 
        sprintf(path, "%s/%s", ANDROID_USB_PATH, android_item[i]);
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            USBMON_ERR("android_item: open  %s error\n",path);
        } else {
            USBMON_DBG("string is %s\n", ptr);
            length = write(fd, ptr, strlen(ptr));
            USBMON_DBG("length is %d\n", length);
            while(*ptr != '\0')
              ptr++;
            ptr++;
            close(fd);
        }  
    }
    /*write f_mass_storage inquiry string*/
    //memset(path, 0, sizeof(path));
    sprintf(path, "%s", MASS_STORAGE_INQUIRY_STRING_PATH);
    fd = open(path, O_WRONLY);
    if(fd < 0){
      USBMON_ERR("open %s error\n",path);
    }
    length = write(fd, inquiry_string, strlen(inquiry_string));
    USBMON_DBG("length is %d  %s\n", length, inquiry_string);
    close(fd);
    
    /*enable*/
    //memset(path, 0, sizeof(path)); 
    sprintf(path, "%s/%s", ANDROID_USB_PATH, "enable");
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        USBMON_ERR("android_item: open  %s error\n",path);
    }
    USBMON_DBG("string is %s\n", ptr);
    length = write(fd, ptr, strlen(ptr));
    USBMON_DBG("length is %d\n", length);
    close(fd);
}

static void process_switch_uevent(struct uevent *uevent)
{
    char cmd[255],usbfilepath[32];

    android_printLog(ANDROID_LOG_DEBUG,"switch event { '%s', '%s', '%s', '%s' }\n", uevent->action, uevent->path, 
                    uevent->subsystem, uevent->switch_state);


    if (!strcmp(uevent->action, "change")) {
        memset(cmd, 0, sizeof(cmd)); 

        if (!strcmp(uevent->switch_state, "USB_B_IN")) {
            usbmon_stats.b_in = 1;
            usbmon_stats.b_in_cnt++;            
            usbmon_stats.install_envent_pend = 1;
            /*�жϴ�����usbϵ�кŵ��ļ��Ƿ񻹴���,������,�򴴽���*/
            sprintf(usbfilepath, "%s", USB_SERIALNUM_PATH);
            if(file_is_exist(usbfilepath) == -1)
              create_usbserialnumber(usbfilepath);
              
        } else if (!strcmp(uevent->switch_state, "USB_B_OUT")) {
            usbmon_stats.b_in = 0;
            usbmon_stats.install_envent_pend = 1;
        } else if (!strcmp(uevent->switch_state, "USB_A_IN")) {
            usbmon_stats.a_in = 1;
            usbmon_stats.install_envent_pend = 1;
        } else if (!strcmp(uevent->switch_state, "USB_A_OUT")) {
            usbmon_stats.a_in = 0;
            usbmon_stats.install_envent_pend = 1;
        }
    }
}

static void process_block_uevent(struct uevent *uevent)
{
    if (!strcmp(uevent->action, "add")) {
    } else if (!strcmp(uevent->action, "remove")) {
    } else if (!strcmp(uevent->action, "change")) {
    } else {
    }

    return;
}

static void parse_3g_dongle(struct uevent *uevent)
{
    char default_vid[5];
    char default_pid[5];
    char check_pid[5];
    char path[255];
    char cmd[255];
    int fd,length,count;

    memset(default_vid, 0, sizeof(default_vid)); 
    memset(default_pid, 0, sizeof(default_pid)); 
    memset(cmd, 0, sizeof(cmd));
    memset(path, 0, sizeof(path));

    sprintf(path,"/sys%s/idVendor",uevent->path);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        USBMON_ERR("usb modeswitch open  %s error",path);
    } else {
        length = read(fd, default_vid, sizeof(default_vid));
        default_vid[length-1] = 0;
        close(fd);
    }

    memset(path, 0, sizeof(path)); 
    sprintf(path,"/sys%s/idProduct",uevent->path);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        USBMON_ERR("usb modeswitch open  %s error",path);
    } else {
        length = read(fd, default_pid, sizeof(default_pid));
        default_pid[length-1] = 0;
        close(fd);
    }

    memset(path, 0, sizeof(path)); 
    sprintf(path,"/system/etc/usb_modeswitch.d/%s_%s",default_vid,default_pid);
    if (file_is_exist(path)) {
        return;
    }

    sprintf(cmd,"/system/xbin/usb_modeswitch -I -W -v %s -p %s -c /system/etc/usb_modeswitch.d/%s_%s",
                default_vid,default_pid,default_vid,default_pid);

    memset(path, 0, sizeof(path)); 
    sprintf(path,"/sys%s/idProduct",uevent->path);
    sleep(2);
    for(count = 0; count < USB_MODESWITCH_RETRY_COUNT; count++){
        USBMON_DBG("usb_modeswitch: cmd=%s", cmd);
        if(system(cmd) < 0)
            USBMON_ERR("usb modeswitch error");
        sleep(1);
        memset(check_pid, 0, sizeof(check_pid)); 
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            USBMON_ERR("check open %s error",path);
            break;
        }else{
            length = read(fd, check_pid, sizeof(check_pid));
            check_pid[length-1] = 0;
            close(fd);
        }
        if (strcmp(check_pid, default_pid)) 
            break;     
    }
    return;
}

/*
 * Host��disconnect��Ϣ��
 * DEVPATH=/devices/platform/actions-dwc3.1/dwc3.0/xhci-hcd/usb1/1-1
 * SUBSYSTEM=usb
 * DEVNAME=bus/usb/001/002
 * DEVTYPE=usb_device
 * ��
 * DEVPATH=/devices/platform/actions-dwc3.1/dwc3.0/xhci-hcd/usb2/2-1
 * SUBSYSTEM=usb
 * DEVNAME=bus/usb/002/002
 * DEVTYPE=usb_device
 */
#define  UHOST_EVENT_PATH_HEAD		"/devices/platform/actions-dwc3"
#define  UHOST_EVENT_PATH			"/devices/platform/actions-dwc3.1/dwc3.0/xhci-hcd/usb%d/%d-1"
#define  UHOST_EVENT_PATH_LEN		30
static void process_uhost_uevent(struct uevent *uevent)
{
    int i = 0;
	char path[255];
    char * event_path = (char*)UHOST_EVENT_PATH_HEAD;

    if (uevent->devtype != NULL) {
        if (!strcmp(uevent->devtype, "usb_device")) {

            /* if path isn't "/devices/platform/actions-dwc3", return out. */
            if (strncmp(uevent->path, event_path, UHOST_EVENT_PATH_LEN)) {
                return;
            }
            android_printLog(ANDROID_LOG_DEBUG,"usbmod","uhost event { '%s', '%s', '%s', '%s' }\n", uevent->action, uevent->path, 
                      uevent->subsystem, uevent->devtype);
            for(i = 1 ; i < 4; i++){
                memset(path, 0, sizeof(path));
                snprintf(path, 254, UHOST_EVENT_PATH, i, i);
                if (!strcmp(uevent->path, path)) {
                    if (!strcmp(uevent->action, "add")) {
                        if (usbmon_stats.a_in == 0) {
                            USBMON_ERR("umonitord uhost event err, a_in is 0.\n");
                        }
                        usbmon_stats.usb_dev_con = 1;
                        usbmon_stats.usb_dev_cnt++;
                        usbmon_stats.install_envent_pend = 1;
                    } else if (!strcmp(uevent->action, "remove")) {
                        usbmon_stats.usb_dev_con = 0;
                        usbmon_stats.usb_dev_cnt--;
                        usbmon_stats.install_envent_pend = 1;
                    } 
                } 
            }
            if (!strcmp(uevent->action, "add"))
                parse_3g_dongle(uevent);
        }
    }
 
    return;
}

int prase_usb_config( void )
{
  char prop_value[32];
  char target_string[4]="adb";
  
  property_get("sys.usb.config", prop_value, "adb");
  if(!strstr(prop_value, target_string))
    return -1;
  return 0;
}

static void process_usbmon_sh(struct uevent *uevent)
{
    char cmd[255];
    char filepath[255];
    int filp,length;

#if 0
    #define SYS_UDC_FILE_PATH	"/sys/udc/gadget"
    #define SYS_HCD_FILE_PATH	"/sys/hcd/usb"
    /* use sys fs to detect usb device revoed or not. */
    struct stat sys_stat;
    int ret = 0;
    int i = 0;

    /* use sys fs to detect usb device revoed or not. */
    if (!strcmp(uevent->switch_state, "USB_B_OUT")) {
        do { 
            ret = stat(SYS_UDC_FILE_PATH, &sys_stat);
            if (ret == 0) {
                usleep(10000);
                i++;
            }
            if (i > 100) {
                USBMON_DBG("wait usb device safely remove timeout!\n");
                break;
            }
        } while (ret == 0);

    } else if (!strcmp(uevent->switch_state, "USB_A_OUT")) {
        do {
            ret = stat(SYS_HCD_FILE_PATH, &sys_stat);
            if (ret == 0) {
                usleep(10000);
                i++;
            }
            if (i > 100) {
                USBMON_DBG("wait usb host safely remove timeout!\n");
                break;
            }
        } while (ret == 0);
    }
#endif

    /* check state is ok. */
    if ((usbmon_stats.uhost_installed != 0) && (usbmon_stats.b_in != 0)) {
        USBMON_ERR("uhost_installed:%d, b_in:%d\n", usbmon_stats.uhost_installed, usbmon_stats.b_in);

        /* force to uninstall xhci_hcd.ko. */
        if(usbmon_stats.usb_dev_cnt > 0) {
            usleep(300000);		/* wait all device removed. */
        }       

        sprintf(cmd, "/usbmond.sh %s", "USB_A_OUT");         
        if(system(cmd) < 0)
            USBMON_ERR("process %s failed\n", cmd);
        usbmon_stats.uhost_installed = 0;
        usbmon_stats.a_in = 0;
        usbmon_stats.usb_dev_con = 0;
        usbmon_stats.usb_dev_cnt = 0;
        usleep(300000);		/* wait drv removed. */
    }
    if ((usbmon_stats.gadget_installed != 0) && (usbmon_stats.a_in != 0)) {
        USBMON_ERR("gadget_installed:%d, a_in:%d\n", usbmon_stats.gadget_installed, usbmon_stats.a_in);

        /* force to uninstall usb gagdet ko. */
        
        sprintf(cmd, "/usbmond.sh %s %d", "USB_B_OUT", 1); 
        if(prase_usb_config() == -1)
          sprintf(cmd, "/usbmond.sh %s %d", "USB_B_OUT", 0);  
                  
       // sprintf(cmd, "/usbmond.sh %s", "USB_B_OUT");
        if(system(cmd) < 0)
            USBMON_ERR("process %s failed\n", cmd);
        usbmon_stats.gadget_installed = 0;
        usbmon_stats.b_in = 0;
        usbmon_stats.g_android_con = 0;
        usleep(300000);		/* wait drv removed. */
    }
    if ((usbmon_stats.gadget_installed != 0) && (usbmon_stats.uhost_installed != 0)) {
        USBMON_ERR("gadget_installed:%d, uhost_installed:%d\n", usbmon_stats.gadget_installed, usbmon_stats.uhost_installed);
    }

    /* process gadget ko install. */
    if (usbmon_stats.gadget_installed != 0) {
        if (usbmon_stats.b_in == 0) { 
            if ((usbmon_stats.b_in_cnt != 1) && (usbmon_stats.g_android_con != 0)) {
                    usleep(100000);	/* wait disconnect. */
            }
            
            android_state_save();            
            sprintf(cmd, "/usbmond.sh %s %d", "USB_B_OUT", 1); 
            if(prase_usb_config() == -1)
              sprintf(cmd, "/usbmond.sh %s %d", "USB_B_OUT", 0);                          
            //sprintf(cmd, "/usbmond.sh %s", "USB_B_OUT");
            if(system(cmd) < 0)
                USBMON_ERR("process %s failed\n", cmd);
            
            android_state_restore();
            usbmon_stats.g_android_con = 0;
            usbmon_stats.gadget_installed = 0;
        }
    } else {
        if (usbmon_stats.b_in != 0) {
          
            android_state_save();
            sprintf(cmd, "/usbmond.sh %s %d", "USB_B_IN", 1); 
            if(prase_usb_config() == -1)
              sprintf(cmd, "/usbmond.sh %s %d", "USB_B_IN", 0);                              
            //sprintf(cmd, "/usbmond.sh %s", "USB_B_IN");
            if(system(cmd) < 0)
                USBMON_ERR("process %s failed\n", cmd);

            usleep(100000);	/* wait sysfs directory valid. */           
                  
//            /*write f_mass_storage inquiry string*/
//            memset(filepath, 0, sizeof(filepath));
//            inquiry_string[16] = '\0';
//            sprintf(filepath, "%s", MASS_STORAGE_INQUIRY_STRING_PATH);
//            printf("filepath : %s  %s\n", filepath, MASS_STORAGE_INQUIRY_STRING_PATH);
//            filp = open(filepath, O_WRONLY);
//            if(filp < 0){
//              printf("open %s error\n",filepath);
//            }
//            length = write(filp, inquiry_string, sizeof(inquiry_string));
//            printf("length is %d  %s\n", length,inquiry_string);
//            close(filp);
//                      
                        
            android_state_restore();                   
            usbmon_stats.gadget_installed = 1;
        }
    }

    /* process uhost ko install. */
    if (usbmon_stats.uhost_installed != 0) {
        if ((usbmon_stats.a_in == 0) && (usbmon_stats.usb_dev_con == 0)) {
            if(usbmon_stats.usb_dev_cnt > 0) {
                usleep(100000);		/* wait all device removed. */
            }
            sprintf(cmd, "/usbmond.sh %s", "USB_A_OUT");
            if(system(cmd) < 0)
                USBMON_ERR("process %s failed\n", cmd);
            usbmon_stats.uhost_installed = 0;
            usbmon_stats.usb_dev_cnt = 0;
        }
    } else {
        if (usbmon_stats.a_in != 0) {
            sprintf(cmd, "/usbmond.sh %s", "USB_A_IN");
            if(system(cmd) < 0)
                USBMON_ERR("process %s failed\n", cmd);
            usbmon_stats.uhost_installed = 1;
        }
    }

    usbmon_stats.install_envent_pend = 0;
    return;
}


static void process_uevent(struct uevent *uevent)
{
    if (!strcmp(uevent->subsystem, "android_usb"))
        process_usb_uevent(uevent);
    else if (!strcmp(uevent->subsystem, "switch"))
        process_switch_uevent(uevent);
    else if (!strcmp(uevent->subsystem, "usb"))
        process_uhost_uevent(uevent);
    //else if (!strcmp(uevent->subsystem, "block"))
        //process_block_uevent(uevent);

    if (usbmon_stats.install_envent_pend == 0) {
        return;
    }
    process_usbmon_sh(uevent);
    return;
}

static void parse_uevent(char *msg, struct uevent *uevent)
{
    uevent->action = "";
    uevent->path = "";
    uevent->subsystem = "";
    uevent->switch_state = "";
    uevent->devtype = "";
    uevent->usb_state = "";

    while(*msg) {
        if(!strncmp(msg, "ACTION=", 7)) {
            msg += 7;
            uevent->action = msg;
        } else if(!strncmp(msg, "DEVPATH=", 8)) {
            msg += 8;
            uevent->path = msg;
        } else if(!strncmp(msg, "SUBSYSTEM=", 10)) {
            msg += 10;
            uevent->subsystem = msg;
        } else if(!strncmp(msg, "SWITCH_STATE=", 13)) {
            msg += 13;
            uevent->switch_state = msg;
        } else if(!strncmp(msg, "DEVTYPE=", 8)) {
            msg += 8;
            uevent->devtype = msg;
        } else if(!strncmp(msg, "USB_STATE=", 10)) {
            msg += 10;
            uevent->usb_state = msg;
	}

        /* advance to after the next \0 */
        while(*msg++)
            ;
    }

}

static int handle_uevent(int fd)
{
    char msg[UEVENT_MSG_LEN+2];
    int n;

    if (fd < 0)
        return -1;

    while (true) {
        struct uevent uevent;

        n = uevent_kernel_multicast_recv(fd, msg, UEVENT_MSG_LEN);
        if (n <= 0) {
            ALOGE("Error recv uevent (%s)", strerror(errno));
            //break;
        }
        if (n >= UEVENT_MSG_LEN)   /* overflow -- discard */
            continue;

        msg[n] = '\0';
        msg[n+1] = '\0';

        parse_uevent(msg, &uevent);
        process_uevent(&uevent);
    }

    return 0;
}

static void do_coldboot(DIR *d)
{
    struct dirent *de;
    int dfd, fd;

    dfd = dirfd(d);

    fd = openat(dfd, "uevent", O_WRONLY);
    if(fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);
        //process_uevent();
    }

    while((de = readdir(d))) {
        DIR *d2;

        if(de->d_type != DT_DIR || de->d_name[0] == '.')
            continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if(fd < 0)
            continue;

        d2 = fdopendir(fd);
        if(d2 == 0)
            close(fd);
        else {
            do_coldboot(d2);
            closedir(d2);
        }
    }
}

static void coldboot(const char *path)
{
    DIR *d = opendir(path);
    if(d) {
        do_coldboot(d);
        closedir(d);
    }
}

static int open_uevent(int buf_sz, bool passcred)
{
    struct sockaddr_nl addr;
    int on = passcred;
    int s;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid() | 1 << 16; //avoid conflict with vold
    addr.nl_groups = 0xffffffff;

    s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if(s < 0)
        return -1;

    setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &buf_sz, sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));

    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }

    return s;
}

int usbmond_main(void) {
    int fd, nr, filehandle,length;
    struct pollfd ufd;
    char filepath[255], usbfilepath[32];
    char enable = '1';
    char usb_enable = '0';
    
    // check usb enable
    sprintf(filepath, "%s", ANDROID_USB_ENABLE_PATH);
    fd = open(filepath, O_RDONLY);
    if(fd < 0){
      USBMON_ERR("open %s error\n", filepath);
    }
    read(fd, &usb_enable, 1);
    close(fd);
    
    if(usb_enable != '1'){
      USBMON_ERR("usb not ready.\n");
      return -1;
    }

    // deamon start
    memset(&usbmon_stats, 0, sizeof(struct usbmon_stats_t)); 
    
    //memset(usbfilepath, 0, sizeof(usbfilepath));        
    sprintf(usbfilepath, "%s", USB_SERIALNUM_PATH);
    if(file_is_exist(usbfilepath) == -1)
      create_usbserialnumber(usbfilepath);
        
    //memset(filepath, 0, sizeof(filepath));
    sprintf(filepath, "%s", MONITOR_PATH);
    filehandle = open(filepath, O_WRONLY);
    if(filehandle < 0){
      USBMON_ERR("open %s error\n", filepath);
    }
    write(filehandle, &enable, 1);
    close(filehandle);
    
    property_get("ro.usb.descriptor", inquiry_string, "google,google,4.10");    
    android_printLog(ANDROID_LOG_DEBUG,"usbmod","INQUIRY_STRING %s",inquiry_string);
    //printf("property_get :%s\n",inquiry_string);
    android_state_save(); 
    
    fd = open_uevent(SOCKET_BUF_SIZE, true);
    if (fd < 0) {
        ALOGE("Error connecting (%s)", strerror(errno));
        return -1;//exit(4);
    }

    ufd.events = POLLIN;
    ufd.fd = fd;

    //coldboot("/sys/monitor");

    while(1) {     
      
        ufd.revents = 0;
        
        nr = poll(&ufd, 1, -1);
        if (nr <= 0)
            continue;            
            
        if (ufd.revents == POLLIN)
               handle_uevent(fd);
    }
    
    return 0;
}
