#if defined(__linux__)

#include "HIDLockdownManager.hpp"
#include <sys/stat.h>
#include <assert.h>

#define UDEV_RULE_PATH "/etc/udev/rules.d/99-typesafely-block-usb.rules"
#define SCRIPT_PATH "/etc/typesafely/handle_new_device.sh"
#define LOCKDOWN_FLAG_PATH "/var/run/typesafely/lockdown_enabled"
#define USB_PRODUCT_CODE "f055/5d3e"
// TODO fix this awful hack
#define USER "harry"

HIDLockdownManager::HIDLockdownManager() {

}

HIDLockdownManager::~HIDLockdownManager() {

}

static bool set_file_contents(const char *path, const char *str) {
    FILE *fp = fopen(path, "w");

    if (!fp) {
        perror("Couldn't open lockdown file for writing");
        return false;
    }

    bool ret = true;

    if (fputs(str, fp) < 0) {
        perror("Couldn't write to lockdown file");
        ret = false;
    }

    fclose(fp);
    return ret;
}

bool HIDLockdownManager::Setup() {
    if (mkdir("/var/run/typesafely", S_IRWXU) != 0 && errno != EEXIST) {
        perror("Couldn't create tmp directory for lockdown");
        return false;
    }

    const char *script_str = "#!/usr/bin/env bash\n"
                             "\n"
                             "set -o errexit\n"
                             "set -o nounset\n"
                             "set -o pipefail\n"
                             "\n"
                             "LOCKDOWN_ENABLED_PATH=\"" LOCKDOWN_FLAG_PATH "\"\n"
                             "\n"
                             "if [[ -f $LOCKDOWN_ENABLED_PATH ]] ; then\n"
                             "   # Race condition in that file might be deleted here, but doesn't matter for this use case\n"
                             "\n"
                             "   flag=$(tr -d \"\\n \" < \"$LOCKDOWN_ENABLED_PATH\")\n"
                             "   if [ \"$flag\" = \"1\" ]; then\n"
                             "       echo 0 > \"/sys/$DEVPATH/authorized\";\n"
                             "       [ \"${PRODUCT:0:9}\" != \"" USB_PRODUCT_CODE "\" ] && su " USER " -c 'notify-send \"TypeSafely\" \"Disabled an insecure USB keyboard.\"' || true \n"
                             "   else\n"
                             "       echo 1 > \"/sys/$DEVPATH/authorized\";\n"
                             "   fi\n"
                             "fi\n";
    bool wrote_script = set_file_contents(SCRIPT_PATH, script_str);
    if (!wrote_script) return false;
    chmod(SCRIPT_PATH, S_IRWXU);

    const char *rule_str = "ACTION==\"add\", "
                           "SUBSYSTEM==\"usb\", "
                           "DRIVER==\"usbhid\", "
                           "ATTRS{bInterfaceClass}==\"03\", "
                           "ATTRS{bInterfaceSubClass}==\"01\", "
                           "ATTRS{bInterfaceProtocol}==\"01\", "
//                           "ATTR{authorized}=\"0\","
                           "RUN+=\"" SCRIPT_PATH "\"";

    bool wrote_udev_rule = set_file_contents(UDEV_RULE_PATH, rule_str);
    if (!wrote_udev_rule) return false;
    chmod(UDEV_RULE_PATH, S_IRWXU);

    if (!set_file_contents(LOCKDOWN_FLAG_PATH, "0")) return false;
    chmod(LOCKDOWN_FLAG_PATH, S_IRWXU);

    return true;
}

bool HIDLockdownManager::SetLockdownLevel(HIDLockdownManager::LockdownLevel level) {
    if (level == LockdownLevel::Unknown) return false;
    lastSetLockdownLevel = level;

    const char *level_str = level == LockdownLevel::DisableUntrustedKeyboards ? "1" : "0";

    bool ret = set_file_contents(LOCKDOWN_FLAG_PATH, level_str);
    system("udevadm control --reload-rules");
    system("udevadm trigger");

    return ret;
}

HIDLockdownManager::LockdownLevel HIDLockdownManager::GetLockdownLevel() {
    assert(false);
    return LockdownLevel::AllowAll;
}

#else

#include "HIDLockdownManager.hpp"
#include <cstdlib>

HIDLockdownManager::HIDLockdownManager() {
}

HIDLockdownManager::~HIDLockdownManager() {

}

bool HIDLockdownManager::Setup() {
    fprintf(stderr, "HIDLockdownManager: current platform does not support restricting HID input. "
                    "Will actually do nothing...\n");
    return true;
}

bool HIDLockdownManager::SetLockdownLevel(HIDLockdownManager::LockdownLevel level) {
    printf("HIDLockdownManager: would set level to %d.\n", level);
    lastSetLockdownLevel = level;
    return true;
}

HIDLockdownManager::LockdownLevel HIDLockdownManager::GetLockdownLevel() {
    return lastSetLockdownLevel;
}

#endif
