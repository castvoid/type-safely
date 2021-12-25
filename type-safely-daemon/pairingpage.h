#pragma once

#include <QtWidgets>

class PairingPage : public QWizardPage {
Q_OBJECT
public:
    PairingPage();
    virtual void initializePage() override;
    virtual void cleanupPage() override;
    virtual bool isComplete() const override;

public slots:
    void displayPin(std::string pin);
    void pinEntryComplete();
    void pinEntrySucceeded();

private:
    QLabel *pin_label;
    bool m_complete;
};
