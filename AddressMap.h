#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _AddressInfo_h
#define _AddressInfo_h

class AddressInfo {
public:
    AddressInfo(void* _addr, size_t _sz, void* _bt[])
        : addr(_addr)
        , sz(_sz)
    {
        if (_bt)
            memcpy(bt, _bt, sizeof(bt));
    }

public:
    void* addr;
    size_t sz;
    void* bt[10];
};

class AddressMap {
public:
    AddressMap()
        : _map(0)
        , _size(0)
        , _max(1024)
    {
    }
    ~AddressMap()
    {
        if (_map) {
            for (size_t i = 0; i < _size; i++)
                delete _map[i];
            free(_map);
        }
        _size = 0;
    }

    bool empty() const { return !_size; } 
    size_t size() const { return _size; }

    AddressInfo* append(void* addr, size_t sz, void* bt[])
    {
        if (!_map) {
            _map = (AddressInfo**)malloc(_max*sizeof(AddressInfo*));
            if (!_map)
                return 0;
        }

        int index = 0;
        if (hasAddr(addr, 0, _size - 1, &index))
            return _map[index];

        AddressInfo* ai = new AddressInfo(addr, sz, bt);
        if (!ai)
            return 0;

        if (_size + 1 > _max) {
            _max += 1024;
            void* r = realloc(_map, _max*sizeof(AddressInfo*));
            if (!r) {
                if (ai)
                    delete ai;
                return 0;
            }
            _map = (AddressInfo**)r;
        }

        if (index < 0) {
            index = 0;
        }

        for (int i = _size - 1; i >= index; i--)
             _map[i+1] = _map[i];

        _map[index] = ai;
        _size++;
        return ai;
    }

    void remove(void* addr)
    {
        int index;
        if (hasAddr(addr, 0, _size - 1, &index)) {
            for (size_t i = index; i < _size - 1; i++)
                _map[i] = _map[i+1];
            _size--;
        }
    }

    AddressInfo* operator[](size_t index) const
    {
        if (!_map || !_size || index >= _size)
            return 0;
        return _map[index];
    }

private:
    bool hasAddr(void* addr, int low, int high, int* index) const
    {
        int mid = low + (high - low) / 2;
        if (low > high) {
            return false;
        }
        void* maddr = _map[mid]->addr;
        if (maddr == addr) {
            *index = mid;
            return true;
        } else if (maddr > addr) {
            if (low == high) {
                *index = low;
                return false;
            }
            *index = mid;
            return hasAddr(addr, low, mid-1, index);
        } else {
            if (low == high) {
                *index = low+1;
                return false;
            }
            *index = mid + 1;
            return hasAddr(addr, mid+1, high, index);
        }
    }

private:
    AddressInfo** _map;
    size_t _size;
    size_t _max;
};

#endif 
