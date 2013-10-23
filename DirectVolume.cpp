/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <string.h>
#include <errno.h>

#include <linux/kdev_t.h>

#define LOG_TAG "DirectVolume"

#include <cutils/log.h>
#include <sysutils/NetlinkEvent.h>

#include "DirectVolume.h"
#include "VolumeManager.h"
#include "ResponseCode.h"
#include "cryptfs.h"

 #define PARTITION_DEBUG

DirectVolume::DirectVolume(VolumeManager *vm, const char *label,
                           const char *mount_point, int partIdx) :
              Volume(vm, label, mount_point) {
    mPartIdx = partIdx;

    mPaths = new PathCollection();
    for (int i = 0; i < MAX_PARTITIONS; i++)
        mPartMinors[i] = -1;
    mPendingPartMap = 0;
    mDiskMajor = -1;
    mDiskMinor = -1;
    mDiskNumParts = 0;

    setState(Volume::State_NoMedia);
}

DirectVolume::~DirectVolume() {
    PathCollection::iterator it;

    for (it = mPaths->begin(); it != mPaths->end(); ++it)
        free(*it);
    delete mPaths;
}

int DirectVolume::addPath(const char *path) {
    mPaths->push_back(strdup(path));
    return 0;
}

void DirectVolume::setFlags(int flags) {
    mFlags = flags;
}

dev_t DirectVolume::getDiskDevice() {
    return MKDEV(mDiskMajor, mDiskMinor);
}

dev_t DirectVolume::getShareDevice() {
    if (mPartIdx != -1) {
#ifdef VOLD_DISC_HAS_MULTIPLE_MAJORS
        int major = getMajorNumberForBadPartition(mPartIdx);
        if(major != -1) {
            SLOGE("getShareDevice() returning correct major: %d, minor: %d", major, mPartMinors[mPartIdx - 1]);
            return MKDEV(major, mPartMinors[mPartIdx - 1]);
        }
        else
#endif
        return MKDEV(mDiskMajor, mPartIdx);
    } else {
        return MKDEV(mDiskMajor, mDiskMinor);
    }
}

void DirectVolume::handleVolumeShared() {
    setState(Volume::State_Shared);
}

void DirectVolume::handleVolumeUnshared() {
    setState(Volume::State_Idle);
}

// strncmp: s2 can contain '*' for fuzzy matching, etc "/dev/*/mmc"
int DirectVolume::astrncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0)
        return (0);
    do {
        if (*s1 != *s2++) {
            // add for s2 fuzzy matching using '*'
            if (*--s2 == '*') {
                // move s1 to next slash
                while ((*s1++ != 0) && (*s1 != '/')) ;
                // move s2 to next slash
                while ((*s2++ != 0) && (*s2 != '/')) ;
                // dec
                --s1;
            } else {
                return (*(unsigned char *)s1 - *(unsigned char *)s2);
            }
        }
        if (*s1++ == 0)
            break;
    } while (--n != 0);
    return (0);
}

int DirectVolume::handleBlockEvent(NetlinkEvent *evt) {
    const char *dp = evt->findParam("DEVPATH");

    PathCollection::iterator  it;
    for (it = mPaths->begin(); it != mPaths->end(); ++it) {
        if (!astrncmp(dp, *it, strlen(*it))) {
            /* We can handle this disk */
            int action = evt->getAction();
            const char *devtype = evt->findParam("DEVTYPE");

            if (action == NetlinkEvent::NlActionAdd) {
                int major = atoi(evt->findParam("MAJOR"));
                int minor = atoi(evt->findParam("MINOR"));
                char nodepath[255];

                snprintf(nodepath,
                         sizeof(nodepath), "/dev/block/vold/%d:%d",
                         major, minor);
                if (createDeviceNode(nodepath, major, minor)) {
                    SLOGE("Error making device node '%s' (%s)", nodepath,
                                                               strerror(errno));
                }
                if (!strcmp(devtype, "disk")) {
                    handleDiskAdded(dp, evt);
                } else {
                    handlePartitionAdded(dp, evt);
                }
            } else if (action == NetlinkEvent::NlActionRemove) {
                if (!strcmp(devtype, "disk")) {
                    handleDiskRemoved(dp, evt);
                } else {
                    handlePartitionRemoved(dp, evt);
                }
            } else if (action == NetlinkEvent::NlActionChange) {
                if (!strcmp(devtype, "disk")) {
                    handleDiskChanged(dp, evt);
                } else {
                    handlePartitionChanged(dp, evt);
                }
            } else {
                    SLOGW("Ignoring non add/remove/change event");
            }

            return 0;
        }
    }
    errno = ENODEV;
    return -1;
}

void DirectVolume::handleDiskAdded(const char *devpath, NetlinkEvent *evt) {
    mDiskMajor = atoi(evt->findParam("MAJOR"));
    mDiskMinor = atoi(evt->findParam("MINOR"));
	SLOGD("handleDiskAdded %d:%d",mDiskMajor,mDiskMinor);

    const char *tmp = evt->findParam("NPARTS");
    if (tmp) {
        mDiskNumParts = atoi(tmp);
    } else {
        SLOGW("Kernel block uevent missing 'NPARTS'");
        mDiskNumParts = 1;
    }
    SLOGD("handleDiskAdded mDiskNumParts <- %d",mDiskNumParts);
    char msg[255];

    int partmask = 0;
    int i;
    for (i = 1; i <= mDiskNumParts; i++) {
        partmask |= (1 << i);
    }
    mPendingPartMap = partmask;

    if (mDiskNumParts == 0) {
#ifdef PARTITION_DEBUG
        SLOGD("Dv::diskIns - No partitions - good to go son!");
#endif
        setState(Volume::State_Idle);

        /* if ums enabled, share volume */
        if (mVm->getUmsSharingCount() > 0) {
            mVm->shareVolume(getLabel(), "ums");
        } else {
            /* send msg: disk inserted */
            snprintf(msg, sizeof(msg), "Volume %s %s disk inserted (%d:%d)",
                     getLabel(), getMountpoint(), mDiskMajor, mDiskMinor);
            mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeDiskInserted,
                                                     msg, false);        
        }
    } else {
#ifdef PARTITION_DEBUG
        SLOGD("Dv::diskIns - waiting for %d partitions (mask 0x%x)",
             mDiskNumParts, mPendingPartMap);
#endif
        setState(Volume::State_Pending);
    }
}

void DirectVolume::handlePartitionAdded(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    SLOGD("handlePartitionAdded %d:%d",major,minor);
    char msg[255];

    int part_num;

    const char *tmp = evt->findParam("PARTN");

    if (tmp) {
        part_num = atoi(tmp);
    } else {
        SLOGW("Kernel block uevent missing 'PARTN'");
        part_num = 1;
    }

    if (part_num > MAX_PARTITIONS || part_num < 1) {
        SLOGE("Invalid 'PARTN' value");
        return;
    }

    // if add partition without add disk, then mount the partition
    //if ((mDiskNumParts == 0) && (mDiskMajor == -1)) {
    /*if (mDiskNumParts == 0){		
        mDiskNumParts = 1;
		SLOGD("add partition without add disk mDiskNumParts <- %d",mDiskNumParts);
		if(mDiskMajor == -1){            
            mDiskMajor = major;
            mDiskMinor = 0;
            mPendingPartMap = (1 << 1);
            part_num = 1;
		}
    }*/

	if ((mDiskNumParts == 0) && (mDiskMajor == -1)) {
    	SLOGD("add partition without add disk mDiskNumParts <- %d",mDiskNumParts);
        mDiskNumParts = 1;		
		mDiskMajor = major;
        mDiskMinor = 0;
        mPendingPartMap = (1 << 1);
        part_num = 1;		
    } else {
    	if(mDiskNumParts < part_num){ 
			SLOGD("mDiskNumParts < part_num mDiskNumParts <- %d",part_num);
			mDiskNumParts = part_num;
			//int partmask = 0;
			//int i;
			//for (i = 1; i <= mDiskNumParts; i++) {
			//	partmask |= (1 << i);
			//}
			//mPendingPartMap = partmask;		
			mPendingPartMap = 1 << part_num;
    	}
    }
    
    // allocate new one if part num is nonsequence
    if (part_num > mDiskNumParts) {
        for (int i = 1; i <= mDiskNumParts; i++) {
            if (mPendingPartMap & (1 << i)) {
                SLOGW("Invalid part num: %d, allocate new: %d", part_num, i);
                part_num = i;
                break;
            }
        }
    }

    if (major != mDiskMajor) {
        SLOGE("Partition '%s' has a different major than its disk!", devpath);
#ifdef VOLD_DISC_HAS_MULTIPLE_MAJORS
        ValuePair vp;
        vp.major = major;
        vp.part_num = part_num;
        badPartitions.push_back(vp);
#else
        return;
#endif
    }
#ifdef PARTITION_DEBUG
    SLOGD("Dv:partAdd: part_num = %d, minor = %d\n", part_num, minor);
#endif
    if (part_num >= MAX_PARTITIONS) {
        SLOGE("Dv:partAdd: ignoring part_num = %d (max: %d)\n", part_num, MAX_PARTITIONS-1);
    } else {
        mPartMinors[part_num -1] = minor;
    }
    mPendingPartMap &= ~(1 << part_num);

    if (!mPendingPartMap) {
#ifdef PARTITION_DEBUG
        SLOGD("Dv:partAdd: Got all partitions - ready to rock!");
#endif
        if (getState() != Volume::State_Formatting) {
            setState(Volume::State_Idle);
            
            /* if ums enabled, share volume */
            if (mVm->getUmsSharingCount() > 0) {
                mVm->shareVolume(getLabel(), "ums");
            } else {
                /* send msg: disk inserted */
                snprintf(msg, sizeof(msg), "Volume %s %s disk inserted (%d:%d)",
                         getLabel(), getMountpoint(), mDiskMajor, mDiskMinor);
                mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeDiskInserted,
                                                         msg, false);  
            }
        }
    } else {
#ifdef PARTITION_DEBUG
        SLOGD("Dv:partAdd: pending mask now = 0x%x", mPendingPartMap);
#endif
    }
}

void DirectVolume::handleDiskChanged(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    SLOGD("handleDiskChanged %d:%d",major,minor);
    if ((major != mDiskMajor) || (minor != mDiskMinor)) {
        return;
    }

    SLOGI("Volume %s disk has changed", getLabel());
    const char *tmp = evt->findParam("NPARTS");
    if (tmp) {
        mDiskNumParts = atoi(tmp);
    } else {
        SLOGW("Kernel block uevent missing 'NPARTS'");
        mDiskNumParts = 1;
    }
	SLOGD("handleDiskChanged mDiskNumParts <- %d",mDiskNumParts);

    int partmask = 0;
    int i;
    for (i = 1; i <= mDiskNumParts; i++) {
        partmask |= (1 << i);
    }
    mPendingPartMap = partmask;

    if (getState() != Volume::State_Formatting) {
        if (mDiskNumParts == 0) {
            setState(Volume::State_Idle);
        } else {
            setState(Volume::State_Pending);
        }
    }
}

void DirectVolume::handlePartitionChanged(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    SLOGD("Volume %s %s partition %d:%d changed\n", getLabel(), getMountpoint(), major, minor);
}

void DirectVolume::handleDiskRemoved(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
	SLOGD("handleDiskRemoved %d:%d",major,minor);
    char msg[255];
    bool enabled;

    if (mVm->shareEnabled(getLabel(), "ums", &enabled) == 0 && enabled) {
        mVm->unshareVolume(getLabel(), "ums");
    }

    /* if partition exist, umount volume in handlePartitionRemoved() */
    int state = getState();
    if (mDiskNumParts > 0) {
        if (state == Volume::State_Mounted) {
            /* if partition still mounted, umount volume again */
            minor = MINOR(mCurrentlyMountedKdev);
            SLOGE("Disk removed but still mounted, umount it again (%d:%d)", major, minor);
        } else {
            setState(Volume::State_NoMedia);
            return;
        }
    }
    
    /* if partition not exist, umount volume now */
    if (state != Volume::State_Mounted && state != Volume::State_Shared) {
        return;
    }
        
    if ((dev_t) MKDEV(major, minor) == mCurrentlyMountedKdev) {
	
        snprintf(msg, sizeof(msg), "Volume %s %s bad removal (%d:%d)",
                 getLabel(), getMountpoint(), major, minor);
        mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeBadRemoval,
                                             msg, false);
											 
        if (mVm->cleanupAsec(this, true)) {
            SLOGE("Failed to cleanup ASEC - unmount will probably fail!");
        }

        if (Volume::unmountVol(true, false)) {
            SLOGE("Failed to unmount volume on bad removal (%s)", 
                 strerror(errno));
            // XXX: At this point we're screwed for now
        } else {
            SLOGD("Crisis averted");
        }        
    } else if (state == Volume::State_Shared) {
        /* removed during mass storage */
        if (mVm->unshareVolume(getLabel(), "ums")) {
            SLOGE("Failed to unshare volume on bad removal (%s)",
                strerror(errno));
        } else {
            SLOGD("Crisis averted");
        }
    }

    setState(Volume::State_NoMedia);
}

void DirectVolume::handlePartitionRemoved(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    char msg[255];
    int state;

    SLOGD("Volume %s %s partition %d:%d removed\n", getLabel(), getMountpoint(), major, minor);

    /*
     * The framework doesn't need to get notified of
     * partition removal unless it's mounted. Otherwise
     * the removal notification will be sent on the Disk
     * itself
     */
    state = getState();
    if (state != Volume::State_Mounted && state != Volume::State_Shared) {
        return;
    }
        
    if ((dev_t) MKDEV(major, minor) == mCurrentlyMountedKdev) {
        /*
         * Yikes, our mounted partition is going away!
         */

        snprintf(msg, sizeof(msg), "Volume %s %s bad removal (%d:%d)",
                 getLabel(), getMountpoint(), major, minor);
        mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeBadRemoval,
                                             msg, false);

	if (mVm->cleanupAsec(this, true)) {
            SLOGE("Failed to cleanup ASEC - unmount will probably fail!");
        }

        if (Volume::unmountVol(true, false)) {
            SLOGE("Failed to unmount volume on bad removal (%s)", 
                 strerror(errno));
            // XXX: At this point we're screwed for now
        } else {
            SLOGD("Crisis averted");
        }
    } else if (state == Volume::State_Shared) {
        /* removed during mass storage */
        snprintf(msg, sizeof(msg), "Volume %s bad removal (%d:%d)",
                 getLabel(), major, minor);
        mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeBadRemoval,
                                             msg, false);

        if (mVm->unshareVolume(getLabel(), "ums")) {
            SLOGE("Failed to unshare volume on bad removal (%s)",
                strerror(errno));
        } else {
            SLOGD("Crisis averted");
        }
    }
}

/*
 * Called from base to get a list of devicenodes for mounting
 */
int DirectVolume::getDeviceNodes(dev_t *devs, int max) {
    SLOGD("getDeviceNodes mDiskNumParts:%d",mDiskNumParts);
    if (mPartIdx == -1) {
        // If the disk has no partitions, try the disk itself
        if (!mDiskNumParts) {
#ifdef PARTITION_DEBUG
			SLOGD("mDiskMinor:%d",mDiskMinor);
#endif
            devs[0] = MKDEV(mDiskMajor, mDiskMinor);
            return 1;
        }

        int i;
        for (i = 0; i < mDiskNumParts; i++) {
            if (i == max)
                break;
#ifdef PARTITION_DEBUG
			SLOGD("mPartMinors:%d %d",i,mPartMinors[i]);
#endif
            devs[i] = MKDEV(mDiskMajor, mPartMinors[i]);
        }
        return mDiskNumParts;
    }
    devs[0] = MKDEV(mDiskMajor, mPartMinors[mPartIdx -1]);
    return 1;
}

#ifdef VOLD_DISC_HAS_MULTIPLE_MAJORS
/*
 * Returns the correct major number for a bad partition.
 * Returns -1 if the partition is good.
 */
int DirectVolume::getMajorNumberForBadPartition(int part_num) {
    SLOGD("Checking for bad partition major number");
    bool found = false;
    android::List<ValuePair>::iterator iterator = badPartitions.begin();
    for(;iterator != badPartitions.end(); iterator++) {
        if((*iterator).part_num == part_num) {
            found = true;
            SLOGD("Found bad partition");
            break;
        }
    }
    if(found == true)
        return (*iterator).major;
    else
        return -1;
}
#endif

/*
 * Called from base to update device info,
 * e.g. When setting up an dm-crypt mapping for the sd card.
 */
int DirectVolume::updateDeviceInfo(char *new_path, int new_major, int new_minor)
{
    PathCollection::iterator it;

    if (mPartIdx == -1) {
        SLOGE("Can only change device info on a partition\n");
        return -1;
    }

    /*
     * This is to change the sysfs path associated with a partition, in particular,
     * for an internal SD card partition that is encrypted.  Thus, the list is
     * expected to be only 1 entry long.  Check that and bail if not.
     */
    if (mPaths->size() != 1) {
        SLOGE("Cannot change path if there are more than one for a volume\n");
        return -1;
    }

    it = mPaths->begin();
    free(*it); /* Free the string storage */
    mPaths->erase(it); /* Remove it from the list */
    addPath(new_path); /* Put the new path on the list */

    /* Save away original info so we can restore it when doing factory reset.
     * Then, when doing the format, it will format the original device in the
     * clear, otherwise it just formats the encrypted device which is not
     * readable when the device boots unencrypted after the reset.
     */
    mOrigDiskMajor = mDiskMajor;
    mOrigDiskMinor = mDiskMinor;
    mOrigPartIdx = mPartIdx;
    memcpy(mOrigPartMinors, mPartMinors, sizeof(mPartMinors));

    mDiskMajor = new_major;
    mDiskMinor = new_minor;
    /* Ugh, virual block devices don't use minor 0 for whole disk and minor > 0 for
     * partition number.  They don't have partitions, they are just virtual block
     * devices, and minor number 0 is the first dm-crypt device.  Luckily the first
     * dm-crypt device is for the userdata partition, which gets minor number 0, and
     * it is not managed by vold.  So the next device is minor number one, which we
     * will call partition one.
     */
    mPartIdx = new_minor;
    mPartMinors[new_minor-1] = new_minor;

    mIsDecrypted = 1;

    return 0;
}

/*
 * Called from base to revert device info to the way it was before a
 * crypto mapping was created for it.
 */
void DirectVolume::revertDeviceInfo(void)
{
    if (mIsDecrypted) {
        mDiskMajor = mOrigDiskMajor;
        mDiskMinor = mOrigDiskMinor;
        mPartIdx = mOrigPartIdx;
        memcpy(mPartMinors, mOrigPartMinors, sizeof(mPartMinors));

        mIsDecrypted = 0;
    }

    return;
}

/*
 * Called from base to give cryptfs all the info it needs to encrypt eligible volumes
 */
int DirectVolume::getVolInfo(struct volume_info *v)
{
    strcpy(v->label, mLabel);
    strcpy(v->mnt_point, mMountpoint);
    v->flags=mFlags;
    /* Other fields of struct volume_info are filled in by the caller or cryptfs.c */

    return 0;
}
