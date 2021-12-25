#include "pairingpage.h"


PairingPage::PairingPage() : QWizardPage(), pin_label(new QLabel), m_complete(false) {
    pin_label->setText("Connecting...");

    auto *layout = new QVBoxLayout;
    layout->addWidget(pin_label);
    this->setLayout(layout);
}

void PairingPage::initializePage() {
    QWizardPage::initializePage();
    m_complete = false;
    this->completeChanged();
}

void PairingPage::cleanupPage() {
    QWizardPage::cleanupPage();
}

bool PairingPage::isComplete() const {
    return m_complete;
}

void PairingPage::displayPin(std::string pin) {
    QString label_str = "PIN: %1";
    label_str = label_str.arg(QString::fromStdString(pin));

    pin_label->setText(label_str);
}

void PairingPage::pinEntryComplete() {
    pin_label->setText("Finalising...");
}

void PairingPage::pinEntrySucceeded() {
    pin_label->setText("Pairing complete!");
    m_complete = true;
    this->completeChanged();
}