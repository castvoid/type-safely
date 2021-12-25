#define _POSIX_C_SOURCE 200809L

#include "TSPGUIApplication.hpp"
#include "usb.h"
#include "TSPGUIWorker.hpp"
#include "TSPPairingWizard.hpp"
#include <time.h>


class USBWorker : public QObject {
Q_OBJECT
public:
    explicit USBWorker();
    ~USBWorker() override;

public slots:
    void process();
signals:
    void usb_connection_status_updated(bool connected, void *device, void *usb_handle);

private:
    void usb_handle_connection_handler(bool connected, void *device, void *handle);
    friend void tsp_gui_usb_handle_connection(bool connected, void *device, void *handle);
};

static USBWorker *current_worker = nullptr;

void tsp_gui_usb_handle_connection(bool connected, void *device, void *handle) {
    if (!current_worker) {
        fprintf(stderr, "current_worker was null?!\n");
        return;
    }

    current_worker->usb_handle_connection_handler(connected, device, handle);
}

USBWorker::USBWorker() {
    current_worker = this;
}

USBWorker::~USBWorker() {
    current_worker = nullptr;
}

void USBWorker::process() {
    current_worker = this;
    usb_setup(tsp_gui_usb_handle_connection);

    struct timespec sleep_time{
        .tv_sec = 0,
        .tv_nsec = 500 * 1000 * 1000
    };

    while (true) {
        usb_tick();
        nanosleep(&sleep_time, nullptr);
    }
}

void USBWorker::usb_handle_connection_handler(bool connected, void *device, void *handle) {
    emit usb_connection_status_updated(connected, device, handle);
}


TSPGUIApplication::TSPGUIApplication(int & argc, char **argv) : QApplication(argc, argv) {

}

static void handle_pairing_event(void *userData, TSPPairingManager::PairingEvent event) {
    TSPGUIApplication *application = (TSPGUIApplication *)userData;
    application->handlePairingEvent(event);
}

int TSPGUIApplication::exec() {
    printf("Exec'd\n");
    TSPGUIApplication::setQuitOnLastWindowClosed(false);
    qRegisterMetaType<uint32_t>("uint32_t");

    auto thread = new QThread;
    auto worker = new USBWorker();
    worker->moveToThread(thread);
    connect(thread, SIGNAL (started()), worker, SLOT (process()));
    connect(worker, SIGNAL (usb_connection_status_updated(bool, void *, void *)), this, SLOT (handle_connection(bool, void *, void *)));
    thread->start();

    pairingManager.SetEventCallback(handle_pairing_event, this);


    lockdownManager.Setup();
    auto num_pairings = pairingManager.getPairedIDs().size();
    auto targetLockdownLevel = num_pairings > 0 ?
        HIDLockdownManager::LockdownLevel::DisableUntrustedKeyboards :
        HIDLockdownManager::LockdownLevel::AllowAll;
    lockdownManager.SetLockdownLevel(targetLockdownLevel);

    return QApplication::exec();
}

void TSPGUIApplication::handle_connection(bool connected, void *dev, void *handle) {
    printf("device %p connection=%d\n", dev, connected);

    if (connected) {
        if (this->gui_workers.find(dev) != this->gui_workers.end()) {
            printf("Duplicate add of device %p\n", dev);
            return;
        }
        auto thread = new QThread;
        auto worker = new TSPGUIWorker(handle, this->pairingManager);
        worker->moveToThread(thread);
        connect(thread, SIGNAL (started()), worker, SLOT (process()));
        connect(worker, &TSPGUIWorker::pairingAvailable, this, &TSPGUIApplication::create_wizard);
        thread->start();

        this->gui_workers.insert(std::pair(dev, worker));
    } else {
        auto it = this->gui_workers.find(dev);
        bool found = ( it != this->gui_workers.end() );

        if (!found) {
            printf("Double delete of device %p\n", dev);
            return;
        }

        it->second->exit();
        this->gui_workers.erase(it);
    }

}

void TSPGUIApplication::create_wizard() {
    printf("Creating wizard!\n");
    TSPGUIWorker *m_sender = (TSPGUIWorker *)sender();

    auto wizard = new TSPPairingWizard;
    connect(m_sender, &TSPGUIWorker::displayPin, wizard, &TSPPairingWizard::displayPin);
    connect(m_sender, &TSPGUIWorker::pinEntryComplete, wizard, &TSPPairingWizard::pinEntryComplete);
    connect(m_sender, &TSPGUIWorker::pairingSucceeded, wizard, &TSPPairingWizard::pinEntrySucceeded);
    wizard->show();

    m_sender->beginPairing(wizard);
}

void TSPGUIApplication::handlePairingEvent(TSPPairingManager::PairingEvent event) {
    auto num_pairings = pairingManager.getPairedIDs().size();
    auto targetLockdownLevel = num_pairings > 0 ?
                               HIDLockdownManager::LockdownLevel::DisableUntrustedKeyboards :
                               HIDLockdownManager::LockdownLevel::AllowAll;

    lockdownManager.SetLockdownLevel(targetLockdownLevel);
}


#include "TSPGUIApplication.moc"
