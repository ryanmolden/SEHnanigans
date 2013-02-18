#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "Dbghelp.h"
#include <vector>
#include <string>

class ImportedFunction
{
public:
    ImportedFunction() : m_pName(nullptr),
                         m_pAddressOfAddress(nullptr)
    { }

    ImportedFunction(const ImportedFunction& refOther) : m_pName(refOther.m_pName),
                                                         m_undecoratedName(refOther.m_undecoratedName),
                                                         m_pAddressOfAddress(refOther.m_pAddressOfAddress)
    { }

    ImportedFunction(ImportedFunction&& refOther) : m_pName(refOther.m_pName),
                                                    m_undecoratedName(std::move(refOther.m_undecoratedName)),
                                                    m_pAddressOfAddress(refOther.m_pAddressOfAddress)
    {
        refOther.m_pName = reinterpret_cast<const char *>(0xDEADBEEF);
        refOther.m_pAddressOfAddress = reinterpret_cast<void*>(0xDEADBEEF);
    }

    ImportedFunction& operator=(const ImportedFunction& refOther)
    {
        m_pName = refOther.m_pName;
        m_undecoratedName = refOther.m_undecoratedName;
        m_pAddressOfAddress = refOther.m_pAddressOfAddress;
        return *this;
    }

    ImportedFunction& operator=(ImportedFunction&& refOther)
    {
        if(&refOther == this)
        {
            return (*this);
        }

        m_pName = refOther.m_pName;
        refOther.m_pName = reinterpret_cast<const char*>(0xDEADBEEF);
        m_undecoratedName = std::move(refOther.m_undecoratedName);
        m_pAddressOfAddress = refOther.m_pAddressOfAddress;
        refOther.m_pAddressOfAddress = reinterpret_cast<void *>(0xDEADBEEF);

        return (*this);
    }

    // Thread safe. Gets the name of the function as it appears in the PE 
    // header info.
    const char *GetName() const { return m_pName; }

    // Not thread safe. Gets the undecorated name of the function.
    std::string GetUndecoratedName()
    {
        if(m_undecoratedName.empty() && m_pName)
        {
            SymSetOptions(SYMOPT_UNDNAME);

            //UNDNAME_NO_MS_KEYWORDS == 'don't show calling conventions'
            //UNDNAME_NO_MEMBER_TYPE == 'don't show static/virtual/etc..'
            const DWORD flags = UNDNAME_NO_ACCESS_SPECIFIERS|
                                UNDNAME_NO_MS_KEYWORDS|
                                UNDNAME_NO_MEMBER_TYPE;

            char buffer[1024];
            const DWORD res = UnDecorateSymbolName(m_pName, 
                                                   &buffer[0], 
                                                   _countof(buffer), 
                                                   flags);
            if(res != 0)
            {
                m_undecoratedName = buffer;
            }
        }

        return m_undecoratedName;
    }

    // Thread safe. Gets an address whose value is the memory location of the 
    // imported function.
    const void *GetAddressOfImportedAddress() const { return m_pAddressOfAddress; }

private:
    friend class ImportAddressTable;

    ImportedFunction(const char *pName, const void *pAddressOfAddress) : m_pName(pName),
                                                                         m_pAddressOfAddress(pAddressOfAddress)
    { }

    const char *m_pName;
    std::string m_undecoratedName;
    const void *m_pAddressOfAddress;
};

class ImportAddressTable 
{
private:
    const char *m_pName;
    std::vector<ImportedFunction> m_functions;
    #if (_MSC_VER >= 1700)
    typedef decltype(m_functions) ContainerType;
    #else
    typedef std::vector<ImportedFunction> ContainerType;
    #endif

public:
    typedef ContainerType::iterator iterator;
    typedef ContainerType::const_iterator const_iterator;
    typedef ContainerType::reverse_iterator reverse_iterator;
    typedef ContainerType::const_reverse_iterator const_reverse_iterator;

    ImportAddressTable() : m_pName(nullptr)
    {}

    ImportAddressTable(const ImportAddressTable& refOther) : m_pName(refOther.m_pName),
                                                             m_functions(refOther.m_functions)
    {}

    ImportAddressTable(ImportAddressTable&& refOther) : m_pName(refOther.m_pName),
                                                        m_functions(std::move(refOther.m_functions))
    {
        refOther.m_pName = reinterpret_cast<const char*>(0xDEADBEEF);
    }

    ImportAddressTable& operator=(const ImportAddressTable& refOther)
    {
        m_pName = refOther.m_pName;
        m_functions = refOther.m_functions;
        return (*this);
    }

    ImportAddressTable& operator=(ImportAddressTable&& refOther)
    {
        if(&refOther == this)
        {
            return (*this);
        }

        m_pName = refOther.m_pName;
        refOther.m_pName = reinterpret_cast<const char*>(0xDEADBEEF);
        m_functions = std::move(refOther.m_functions);

        return (*this);
    }

    const char *GetName() const { return m_pName; }

    iterator begin()
    {
        return m_functions.begin();
    }

    const_iterator cbegin() const
    {
        return m_functions.cbegin();
    }

    reverse_iterator rbegin()
    {
        return m_functions.rbegin();
    }

    const_reverse_iterator rbegin() const
    {
        return m_functions.rbegin();
    }

    iterator end()
    {
        return m_functions.end();
    }

    const_iterator cend() const
    {
        return m_functions.cend();
    }

    reverse_iterator rend()
    {
        return m_functions.rend();
    }

    const_reverse_iterator rend() const
    {
        return m_functions.rend();
    }

private:
    friend class ImportAddressTables;

    ImportAddressTable(const IMAGE_DOS_HEADER *pBaseHeader,
                       const char *pName, 
                       const IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor) : m_pName(pName)
    {
        // OriginalFirstThunk == unbound IAT
        const DWORD offsetNameTable = pImportDescriptor->OriginalFirstThunk;

        // FirstThunk == bound IAT
        const DWORD offsetAddressTable = pImportDescriptor->FirstThunk;

        const char *pIDHChar = reinterpret_cast<const char*>(pBaseHeader);

        const IMAGE_THUNK_DATA *pNameTable = reinterpret_cast<const IMAGE_THUNK_DATA *>(pIDHChar + offsetNameTable);
        const IMAGE_THUNK_DATA *pAddressTable = reinterpret_cast<const IMAGE_THUNK_DATA *>(pIDHChar + offsetAddressTable);

        for(int current = 0 ; pNameTable[current].u1.AddressOfData != 0 ; ++current)
        {
            // The Hint/Name table entries have the following format (which 
            // explains the weird +2 when grabbing the imported function name)
            //
            // offset          size          value          description
            // 0                2            Hint           Index into export name pointer table.
            // 2             variable        Name           ASCII string containing the name of the function to import.
            // *              0 or 1         Pad            A trailing zero-pad byte, if necessary, to align the next entry.
            const char *pName = (pIDHChar + (2 + pNameTable[current].u1.AddressOfData));
            const void *pTarget = &(pAddressTable[current].u1.Function);

            // NOTE: std::move isn't really beneficial here as initially the struct
            // only has two raw, non-owning pointers for the member fields, but 
            // it doesn't hurt and would be beneficial in the future if I beefed 
            // up the struct, made it eagerly get the undecorated name, etc..
            // I can't emplace_back here as std::vector can't call the private
            // ctor on ImportedFunction, and making std::vector a friend seemed
            // weird somehow.
            m_functions.push_back(std::move(ImportedFunction(pName, pTarget)));
        }
    }
};