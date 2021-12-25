#pragma once

#include <stddef.h>
#include "Platform.hpp"

template<typename T, size_t len> class CircularBuffer {

private:
    static inline size_t nextIndex(size_t n) {
        return (n+1) % len;
    }

protected:
    T buf[len];
    size_t indexWrite;
    size_t indexRead;

public:
    CircularBuffer() : indexWrite(0), indexRead(0) { }

    bool queue(const T element) {
        bool succeeded = false;

        auto initial = Platform::Atomic::EnterCritical();
        if (nextIndex(indexWrite) != indexRead) {
            indexWrite = nextIndex(indexWrite);
            buf[indexWrite] = element;
            succeeded = true;
        }
        Platform::Atomic::ExitCritical(initial);

        return succeeded;
    }

    bool dequeue(T *valPtr) {
        bool succeeded = false;

        auto initial = Platform::Atomic::EnterCritical();
        if (indexRead != indexWrite) {
            indexRead = nextIndex(indexRead);
            *valPtr = buf[indexRead];
            succeeded = true;
        }
        Platform::Atomic::ExitCritical(initial);

        return succeeded;
    }

    bool isEmpty() {
        auto initial = Platform::Atomic::EnterCritical();
        bool isEmpty = indexWrite == indexRead;
        Platform::Atomic::ExitCritical(initial);

        return isEmpty;
    }
};
