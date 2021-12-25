#pragma once

#include <QWizard>
#include "pairingpage.h"

class TSPPairingWizard : public QWizard {
Q_OBJECT

public:
    TSPPairingWizard();

public
slots:
    void displayPin(uint32_t pin);
    void pinEntryComplete();
    void pinEntrySucceeded();
signals:
    void initiatePairing();
    void wizardDone();

private:
    PairingPage page_pairing;
    void pageIdChanged(int id);
};
