#pragma once

#include <QtWidgets>
#include <map>
#include "TSPGUIWorker.hpp"
#include "HIDLockdownManager.hpp"

#define TYPESAFELY_APP_PATH "/etc/typesafely/"

class TSPGUIApplication : public QApplication {
Q_OBJECT

public:
    TSPGUIApplication(int &argc, char *argv[]);

    int exec();
    void handlePairingEvent(TSPPairingManager::PairingEvent event);

public slots:
    void handle_connection(bool connected, void *dev, void *handle);
    void create_wizard();

private:
    std::map<void*, TSPGUIWorker*> gui_workers{};
    TSPPairingManager pairingManager{TYPESAFELY_APP_PATH};
    HIDLockdownManager lockdownManager;
};
