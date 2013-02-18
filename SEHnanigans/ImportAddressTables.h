#pragma once
#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>
#include "ImportAddressTable.h"
#include <vector>

class ImportAddressTables
{
private:
    std::vector<ImportAddressTable> m_importTables;

#if (_MSC_VER >= 1700)
    typedef decltype(m_importTables) ContainerType;
#else
    typedef std::vector<ImportAddressTable> ContainerType;
#endif

public:
    typedef ContainerType::iterator iterator;
    typedef ContainerType::const_iterator const_iterator;
    typedef ContainerType::reverse_iterator reverse_iterator;
    typedef ContainerType::const_reverse_iterator const_reverse_iterator;

    ImportAddressTables(nullptr_t pTargetModule)
    {
        Initialize(GetModule(static_cast<LPCSTR>(pTargetModule)));
    }

    ImportAddressTables(LPCSTR pTargetModule)
    {
        Initialize(GetModule(pTargetModule));
    }

    ImportAddressTables(LPCWSTR pTargetModule)
    {
        Initialize(GetModule(pTargetModule));
    }

    ImportAddressTables(ImportAddressTables&& refOther) : m_importTables(std::move(refOther.m_importTables))
    {
    }

    ImportAddressTables operator=(ImportAddressTables&& refOther)
    {
        if(&refOther == this)
        {
            return (*this);
        }

        m_importTables = std::move(refOther.m_importTables);

        return (*this);
    }

    iterator begin()
    {
        return m_importTables.begin();
    }

    const_iterator cbegin() const
    {
        return m_importTables.cbegin();
    }

    reverse_iterator rbegin()
    {
        return m_importTables.rbegin();
    }

    const_reverse_iterator rbegin() const
    {
        return m_importTables.rbegin();
    }

    iterator end()
    {
        return m_importTables.end();
    }

    const_iterator cend() const
    {        
        return m_importTables.cend();
    }

    reverse_iterator rend()
    {
        return m_importTables.rend();
    }

    const_reverse_iterator rend() const
    {
        return m_importTables.rend();
    }

private:
    void Initialize(HMODULE targetModule)
    {
        if(targetModule == 0)
        {
            return;
        }

        const IMAGE_DOS_HEADER* pIDH = reinterpret_cast<const IMAGE_DOS_HEADER*>(targetModule);

        const char *pIDHChar = reinterpret_cast<const char*>(pIDH);
        const IMAGE_NT_HEADERS *pINH = reinterpret_cast<const IMAGE_NT_HEADERS*>(pIDHChar + pIDH->e_lfanew);

        if(pINH->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        {
            // No imports.
            return;
        }

        auto const& importDir = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if(importDir.Size == 0)
        {
            // No Imports.
            return;
        }

        const IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(pIDHChar + importDir.VirtualAddress);

        for(int current = 0; pImportDescriptor[current].Name != 0 ; ++current)
        {
            const char *pName = pIDHChar + pImportDescriptor[current].Name;
            m_importTables.push_back(std::move(ImportAddressTable(pIDH, 
                                                                  pName,
                                                                  &pImportDescriptor[current])));
        }
    }

    HMODULE GetModule(LPCWSTR pTargetModule) { return ::GetModuleHandleW(pTargetModule); }

    HMODULE GetModule(LPCSTR pTargetModule) { return ::GetModuleHandleA(pTargetModule); }
};