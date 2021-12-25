#pragma once

#include <QWidget>
#include "TSPPairingWizard.hpp"
#include "TSPPairingManager.hpp"

class TSPGUIWorker : public QObject {
Q_OBJECT
public:
    explicit TSPGUIWorker(void *handle, TSPPairingManager &pairingManager);
    ~TSPGUIWorker() override;
    TSPPairingWizard *getWizard();
    bool readyToPair();
    void exit();

public slots:
    void process();
    void beginPairing(TSPPairingWizard *wizard);
signals:
    void pairingAvailable();
    void displayPin(uint32_t pin);
    void pinEntryComplete();
    void pairingSucceeded();

private:
    bool first = true;
    bool should_exit = false;
    void *handle;
    TSPPairingWizard *wizard = nullptr;
    bool pairing_ok = false;
    TSPPairingManager &pairingManager;
};
