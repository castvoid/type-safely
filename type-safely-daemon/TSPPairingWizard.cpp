#include <utility>
#include <inttypes.h>
#include <assert.h>

#include <QLabel>
#include <QVBoxLayout>
#include "TSPPairingWizard.hpp"
#include "pairingpage.h"

enum {
    kPageIntro,
    kPagePairing,
    kPageDone
};

static QWizardPage *createIntroPage(QWizard *wizard) {
    QWizardPage *page = new QWizardPage;
    page->setTitle("Introduction");

    QLabel *label = new QLabel(
        "Welcome to the TypeSafely Setup Assistant."
    );
    label->setWordWrap(true);
    auto font = label->font();
    font.setBold(true);
    label->setFont(font);

    QString label2_str = "This application will help you to set up your TypeSafely keyboard. "
                         "To begin, press %1.";
    label2_str = label2_str.arg(wizard->buttonText(QWizard::NextButton));

    QLabel *label2 = new QLabel(label2_str);
    label2->setWordWrap(true);

    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(label);
    layout->addWidget(label2);
    page->setLayout(layout);

    return page;
}

QWizardPage *createConclusionPage() {
    QWizardPage *page = new QWizardPage;
    page->setTitle("Conclusion");

    QLabel *label = new QLabel("Your keyboard is now ready to use. Have a nice day!");
    label->setWordWrap(true);

    QVBoxLayout *layout = new QVBoxLayout;
    layout->addWidget(label);
    page->setLayout(layout);

    return page;
}


TSPPairingWizard::TSPPairingWizard() : QWizard() {
    // TODO: free created pages!!!
    this->setWindowTitle("TypeSafely Setup Assistant");
    this->setPage(kPageIntro, createIntroPage(this));
    this->setPage(kPagePairing, &(this->page_pairing));
    this->setPage(kPageDone, createConclusionPage());
    connect(this, &QWizard::currentIdChanged, this, &TSPPairingWizard::pageIdChanged);
}

void TSPPairingWizard::displayPin(uint32_t pin) {
    char str_buf[7]{};
    int written = snprintf(str_buf, sizeof(str_buf), "%06" PRIu32, pin);
    assert(written == 6);

    this->page_pairing.displayPin(str_buf);
}

void TSPPairingWizard::pinEntryComplete() {
    this->page_pairing.pinEntryComplete();
}

void TSPPairingWizard::pinEntrySucceeded() {
    this->page_pairing.pinEntrySucceeded();
}

void TSPPairingWizard::pageIdChanged(int id) {
    printf("PAGE = %d\n", id);

    if (id == kPagePairing) {
        emit initiatePairing();
    } else if (id == -1) {
        emit wizardDone();
    }
}
