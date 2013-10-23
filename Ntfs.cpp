/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright (C) 2012 Freescale Semiconductor, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/mount.h>

#include <linux/kdev_t.h>
#include <logwrap/logwrap.h>
#include "VoldUtil.h"

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Ntfs.h"
#include "VoldUtil.h"

#define NTFS_SUPER_MAGIC 0x5346544e
static char FSCK_NTFS_PATH[] = HELPER_PATH "fsck_ntfs";
static char NTFS_MOUNT_PATH[] = HELPER_PATH "ntfs-3g";
static char MKNTFS_PATH[] = HELPER_PATH "mkntfs";
extern "C" int mount(const char *, const char *, const char *, unsigned long, const void *);

int Ntfs::identify(const char *fsPath) {
    int rc = -1;
    int fd;
    char *devpath;
    int s_magic = 0;

    if ((fd = open(fsPath, O_RDWR)) < 0) {
        SLOGE("Unable to open device '%s' (%s)", fsPath,
             strerror(errno));
        return -1;
    }

    if (lseek(fd, 3, SEEK_SET) < 0) {
        SLOGE("Unable to lseek to get superblock (%s)", strerror(errno));
        rc =  -1;
        goto out;
    }

    if (read(fd, &s_magic, sizeof(s_magic)) != sizeof(s_magic)) {
        SLOGE("Unable to read superblock (%s)", strerror(errno));
        rc =  -1;
        goto out;
    }

    if (s_magic == NTFS_SUPER_MAGIC) {
        rc = 0;
		SLOGI("Ntfs System(%s) Identify success.", fsPath);
    } else
        rc = -1;
out:
    close(fd);
    return rc;
}

/* Current We don't support Ntfs Check support */
int Ntfs::check(const char *fsPath) {
    bool rw = true;
    if (access(FSCK_NTFS_PATH, X_OK)) {
        SLOGW("Skipping ntfs checks\n");
        return 0;
    }

    return 0;
}

int Ntfs::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, bool executable, 
                 int ownerUid, int ownerGid, int permMask, bool createLost) {
    int rc;
    unsigned long flags;
    char mountData[255];

    flags = MS_NODEV | MS_NOSUID | MS_DIRSYNC | MS_NOATIME | MS_NODIRATIME;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    /*
     * Note: This is a temporary hack. If the sampling profiler is enabled,
     * we make the SD card world-writable so any process can write snapshots.
     *
     * TODO: Remove this code once we have a drop box in system_server.
     */
    char value[PROPERTY_VALUE_MAX];
    property_get("persist.sampling_profiler", value, "");
    if (value[0] == '1') {
        SLOGW("The SD card is world-writable because the"
            " 'persist.sampling_profiler' system property is set to '1'.");
        permMask = 0;
    }
    /* FIXME force to world-writable */
    sprintf(mountData,
            "nls=utf8,uid=%d,gid=%d,fmask=%o,dmask=%o",
            ownerUid, ownerGid, permMask, permMask);

    rc = mount(fsPath, mountPoint, "ntfs", flags, mountData);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "ntfs", flags, mountData);
    }

    if (rc == 0 && createLost) {
        char *lost_path;
        asprintf(&lost_path, "%s/LOST.DIR", mountPoint);
        if (access(lost_path, F_OK)) {
            /*
             * Create a LOST.DIR in the root so we have somewhere to put
             * lost cluster chains (fsck_msdos doesn't currently do this)
             */
            if (mkdir(lost_path, 0755)) {
                SLOGE("Unable to create LOST.DIR (%s)", strerror(errno));
            }
        }
        free(lost_path);
    }

    return rc;
}

/* Don't Support NTFS Format */
int Ntfs::format(const char *fsPath, unsigned int numSectors) {
    return -1;
}
