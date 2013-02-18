#include <vector>
#include <algorithm>
#include <iterator>
#include <memory>
#include <excpt.h>
#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>
#include "ImportAddressTables.h"

#ifdef WIN64
#error "The technique for SEH handling this code applies to only exists on 32 bit versions of Windows."
#endif

#if (_MSC_VER < 1600)
#error "Visual Studio Versions prior to 2010 are not supported by this code."
#endif

#if (_WIN32_WINNT < 0x0602)
// This struct doesn't appear to be in the Window's SDK that ships with 2010,
// the SDK for 2012 does have it defined.
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;
#endif

using namespace std;

namespace
{
    #define EXCEPTION_CHAIN_END ((EXCEPTION_REGISTRATION_RECORD*)-1)

    const char newLineString[] = "\r\n";
    const char emptyString[] = "";
    const char formatString[] = "%s%sHandler thunk #%d redirecting to original handler at 0x%x\r\n";
    const char handlerSearchString[] = "Handler Search: ";
    const char unwindString[] = "Unwinding: ";

    // Responsible for freeing my heap-allocated thunk memory once the program 
    // closes down.
    void VirtualAllocDeleter(void *pMem)
    {
        if(pMem != nullptr)
        {
            // dwSize must be 0 since we are using MEM_RELEASE (per MSDN).
            if(!VirtualFree(pMem, /*dwSize*/ 0, MEM_RELEASE))
            {
                printf("VirtualFree Error: 0x%x\n", GetLastError());
            }
        }
    }

    // Held here globally (ewwww) to avoid having to pass it back down the long 
    // chain to someone that will live through the unwind, or have the root of 
    // the stack have to have knowledge about how much  memory to allocate for 
    // all the thunks.
    unique_ptr<void, decltype(&VirtualAllocDeleter)> g_pThunkMem(nullptr, &VirtualAllocDeleter);

    // Way to generate a null-ref. Had it local to the leaf frame originally but 
    // the optimizer in ret builds would eliminate the code sequence.
    volatile int *globalNull;

    // Gets the address for the jump-thunk for printf that we have in our IAT.
    const void *GetImportAddressForPrintf()
    {
        const char * pCrtModName = nullptr;
        
        #ifdef _DEBUG
        #if (_MSC_VER == 1700)
        pCrtModName = "msvcr110d.dll";
        #elif(_MSC_VER == 1600)
        pCrtModName = "msvcr100d.dll";
        #else
        #error "Unsupported version of Visual Studio."
        #endif
        #else
        #if (_MSC_VER == 1700)
        pCrtModName = "msvcr110.dll";
        #elif (_MSC_VER == 1600)
        pCrtModName = "msvcr100.dll";
        #else
        #error "Unsupported version of Visual Studio."
        #endif
        #endif

        const void *pCandidate = nullptr;
        ImportAddressTables tables(nullptr);

        auto tableIter = find_if(begin(tables), end(tables),
                                 [pCrtModName](const ImportAddressTable& refT) 
                                 { return _strcmpi(pCrtModName, refT.GetName()) == 0; });

        if(tableIter != end(tables))
        {
            auto funcIter = find_if(begin(*tableIter), end(*tableIter),
                                    [](const ImportedFunction& refF) 
                                    { return _strcmpi("printf", refF.GetName()) == 0; });

            if(funcIter != end(*tableIter))
            {
                pCandidate = funcIter->GetAddressOfImportedAddress();
            }
        }

        return pCandidate;
    }

    // Simple helper to wrap up the instruction generation to make the code that
    // constructs the thunks a little more readable.
    struct X86InstructionHelper
    {    
        static void GeneratePushAddressOpCode(const void *pAddress, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x68);
            EncodePointerValue(pAddress, byteStream);
        }

        static void GeneratePushImmediate32BitOpCode(int immediateValue, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x68);
            EncodePointerValue(&immediateValue, byteStream);
        }

        static void GenerateJumpImmediateOpCode(int jumpOffset, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0xE9);
            EncodePointerValue(&jumpOffset, byteStream);
        }

        static void GenerateCallImmediateOpCode(void *pTarget, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0xFF);
            byteStream.push_back(0x15);
            EncodePointerValue(pTarget, byteStream);
        }

        static void GenerateAddEspOpCode(BYTE amount, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x83);
            byteStream.push_back(0xC4);
            byteStream.push_back(amount);
        }

        static void GenerateJumpNotEqualOpCode(BYTE amount, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x75);
            byteStream.push_back(amount);
        }

        static void GenerateCompareEaxOpCode(BYTE comparisonValue, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x83);
            byteStream.push_back(0xF8);
            byteStream.push_back(comparisonValue);
        }

        static void GenerateMovEspPlusOffsetToEaxOpCode(BYTE offset, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x8B);
            byteStream.push_back(0x44);
            byteStream.push_back(0x24);
            byteStream.push_back(offset);
        }

        static void GenerateMovEaxPlusOffsetToEaxOpCode(BYTE offset, vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x8b);
            byteStream.push_back(0x40);
            byteStream.push_back(offset);
        }

        static void GenerateJumpViaEaxOpCode(vector<BYTE>& byteStream)
        {
            byteStream.push_back(0xFF);
            byteStream.push_back(0xE0);
        }

        static void GeneratePopEaxOpCode(vector<BYTE>& byteStream)
        {
            byteStream.push_back(0x58);
        }

    private:
        static void EncodePointerValue(const void *pValue, vector<BYTE>& byteStream)
        {
            const char *pByteStart = reinterpret_cast<const char*>(pValue);
            const char *pByteEnd = pByteStart + sizeof(void*);
            byteStream.insert(end(byteStream), pByteStart, pByteEnd);
        }
    };

    // Takes a range of exception registration records and patches each 
    // registered callback with a generated thunk.
    template <typename TIter>
    DWORD PatchExceptionHandlerChain(TIter first, TIter last)
    {    
        // The basic idea here is to allocate a page in memory that is
        // read/write/execute, write out my mini-thunks for each existing SEH 
        // handler to there. The mini-thunks are trivial, they simply push the 
        // real SEH handler address they replaced, their handler id, and a couple 
        // of strings for a printf call. They then do an unconditional jump to 
        // the 'main thunk'. The main thunk simply calls printf to print out a 
        // message saying whether we are on a handler search path or an unwind 
        // path, the handler id and the original target callback it will jump to.
        // Then it does an unconditional jump to the original SEH handler.

        // Get the address of printf so my thunk can call into it. Since we are 
        // generating the actual machine instructions for each thunk we have to 
        // do things (like locate/call printf) 'the hard way'.
        const void *pPrintfTarget = GetImportAddressForPrintf();
        if(pPrintfTarget == nullptr)
        {
            printf("Failed to find printf in our IAT!\r\n");
            return -1;
        }

        const int JumpToInstructionSizeInBytes = 5;

        DWORD res = ERROR_SUCCESS;
        vector<BYTE> thunkBytes;

        const int totalHandlerCount = distance(first, last);

        // These will be allocated in the loop below by the first thunk that 
        // needs to copy its memory over, this allows the size calculations to 
        // appear in a spot that has minimal dependence on knowing, ahead of 
        // time, various instruction stream sizes (which is a real pain if you 
        // change the thunk bodies and have to remember to update the various 
        // places that had encoded their old size into calculations/offsets).
        DWORD thunkMemSizeInBytes = 0;
        LPVOID pCur = nullptr;
        for(auto iter = first ; iter < last ; ++iter)
        {
            const int currentHandlerId = distance(iter, last);

            PEXCEPTION_ROUTINE *pTarget = *iter;

            // Push the target address onto the stack for our main thunk body to 
            // use in its printf call as well as its unconditional jump.
            X86InstructionHelper::GeneratePushAddressOpCode(pTarget, thunkBytes);

            // Push the handler id (value for the %d in the format string) onto 
            // the stack.
            X86InstructionHelper::GeneratePushImmediate32BitOpCode(currentHandlerId, thunkBytes);

            // The EXCEPTION_RECORD* is at esp + 4 on entry into the handler, 
            // but we have already mucked with ESP so it is now at esp + 12. We 
            // need to retreive it, and then retrieve the ExceptionFlags field 
            // and use that to determine which action string we should push onto 
            // the stack.
            X86InstructionHelper::GenerateMovEspPlusOffsetToEaxOpCode(/*offset*/ 12, thunkBytes);
            X86InstructionHelper::GenerateMovEaxPlusOffsetToEaxOpCode(/*offset*/ 4, thunkBytes);

            // This code sequence is, less than crystal clear :) The idea is that 
            // if we are in a handler search phase (i.e. EceptionFlags == 0) then 
            // we want to push one string on the stack (handlerSearchString), if 
            // we are in the unwind phase we want to push another (unwindString). 
            // The assembly sequence this whole chunk generates is (obviously with 
            // different addresses):
            //
            // 0010000E 83 F8 00             cmp         eax,0  
            // 00100011 75 0A                jne         0010001D  
            // 00100013 68 04 FA A1 00       push        0A1FA04h  ;(handlerSearchString)
            // 00100018 E9 05 00 00 00       jmp         00100022  
            // 0010001D 68 58 FA A1 00       push        0A1FA58h  ;(unwindString)
            // 00100022 68 00 FA A1 00       push        0A1FA00h  ;(newLineOrEmptyStrPtrValue)
            X86InstructionHelper::GenerateCompareEaxOpCode(/*comparisonValue*/ 0, thunkBytes);
            X86InstructionHelper::GenerateJumpNotEqualOpCode(/*offset*/ 10, thunkBytes);

            const int handerSearchStrPtrValue = reinterpret_cast<int>(&handlerSearchString[0]);
            X86InstructionHelper::GeneratePushAddressOpCode(&handerSearchStrPtrValue, thunkBytes);

            X86InstructionHelper::GenerateJumpImmediateOpCode(/*offset*/ 5, thunkBytes);

            const int unwindStrPtrValue = reinterpret_cast<int>(&unwindString[0]);
            X86InstructionHelper::GeneratePushAddressOpCode(&unwindStrPtrValue, thunkBytes);

            // Push either the newline string if this is the first handler to 
            // print out, or the empty string if it is not, just to make our output 
            // a little more readable/pretty.
            const bool isTopmostHandler = (currentHandlerId == totalHandlerCount);
            int newLineOrEmptyStrPtrValue = reinterpret_cast<int>(isTopmostHandler ? 
                                                                  &newLineString[0] : 
                                                                  &emptyString[0]);
            X86InstructionHelper::GeneratePushAddressOpCode(&newLineOrEmptyStrPtrValue, thunkBytes);

            // Capture the size of our body up to this point. We need this for 
            // jump calculations below and for pointer advancement to write out 
            // the next thunk.
            const int preJumpThunkBodySize = thunkBytes.size();
            if(currentHandlerId != 1)
            {
                // The offset is the amount necessary to jump from our current 
                // mini-thunk body to the main thunk body. The current size of 
                // the thunkBytes vector is the size of this thunk but doesn't 
                // include the 5 bytes we need for the jump instruction. So the 
                // proper jump distance to the main thunk is:
                //
                //  ((currentHandlerId - 1) * (preJumpThunkBodySize + JumpToInstructionSizeInBytes)) - JumpToInstructionSizeInBytes
                //
                // The handlerId - 1 is because we are emitting the jump at the 
                // end of this mini-thunk, so we don't need to account for its 
                // size in the jump amount. The - JumpToInstructionSizeInBytes 
                // at the end is to account for the fact that the last mini-thunk 
                // simply flows into the primary thunk body, it doesn't jump into 
                // it, so it has no jump instruction.
                const int jumpDistance = ((currentHandlerId - 1) * (preJumpThunkBodySize + JumpToInstructionSizeInBytes)) - JumpToInstructionSizeInBytes;

                // Do a near jump to hurdle the other thunk handlers and hit the 
                // 'main' thunk.
                X86InstructionHelper::GenerateJumpImmediateOpCode(/*offset*/ jumpDistance, thunkBytes);
            }

            if(pCur == nullptr)
            {
                // The main thunk body size is 17 bytes, this is the one place 
                // where forward knowledge is encoded and would need to be updated 
                // if the main thunk body byte count changes. It is simply the 
                // number of instruction bytes it takes to push the format string, 
                // call printf, fix esp, pop into eax and then jump via eax.
                const int mainThunkBodySizeInBytes = 17;
                thunkMemSizeInBytes = (thunkBytes.size() * (totalHandlerCount - 1)) + preJumpThunkBodySize + mainThunkBodySizeInBytes;

                pCur = VirtualAlloc(/*lpAddress*/ nullptr, 
                                    thunkMemSizeInBytes, 
                                    MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_EXECUTE_READWRITE);
                if(pCur == nullptr)
                {
                    printf("VirtuaAlloc failed to allocated memory.");
                    return ERROR_OUTOFMEMORY;
                }

                // Hand off ownership to our global so that the thunk memory 
                // will live beyond all handler searches and unwinds.
                g_pThunkMem.reset(pCur);
            }

            memcpy(pCur, thunkBytes.data(), thunkBytes.size());
            thunkBytes.clear();

            // Replace the registred SEH handler callback with our generated 
            // thunk.
            *pTarget = reinterpret_cast<PEXCEPTION_ROUTINE>(pCur);

            // Advance our pointer so we can write out the next thunk (or the 
            // main thunk body if this is the last handler to be generated).
            pCur = reinterpret_cast<BYTE*>(pCur) + (preJumpThunkBodySize + ((currentHandlerId == 1) ? 0 : JumpToInstructionSizeInBytes));
        }

        // Now write the main thunk that all the mini-thunks thunk to (it's 
        // thunks all the way down!!)
        //
        // We know our exception handler callback routine (our thunk) is cdecl, 
        // which means the caller is responsible for saving eax, ecx and edx, and 
        // no params are passed that way, so we can use those for scratch 
        // registers to prepare ourselves here in our main thunk body.

        // Step 1: Push the address of the format string onto the stack to 
        // complete the stack setup for our call to printf.
        const int formatStrPtrValue = reinterpret_cast<int>(&formatString[0]);
        X86InstructionHelper::GeneratePushAddressOpCode(&formatStrPtrValue, thunkBytes);

        // Step 2: Call printf.
        X86InstructionHelper::GenerateCallImmediateOpCode(&pPrintfTarget, thunkBytes);

        // Step 3: Clean up after the printf call. We want to get our target 
        // address into eax, we know the stack currently consists (at the top) 
        // of the format string address, the newline\empty string address, the 
        // handler id and the target address, in that order. We don't care about 
        // the format string address, the newline\empty string address or the 
        // handler id, so we can just adjust esp to throw those away. Then all 
        // we have to do is pop into eax to retrieve our target address.
        X86InstructionHelper::GenerateAddEspOpCode(/*amount*/ 16, thunkBytes);

        // Step 4: Do an unconditional jump to the original handler target 
        // address, which will have the effect  of 'erasing' the fact we were 
        // ever in this thunk by jumping to the original and having its ret 
        // instruction take us back to the original caller of our thunk (the OS 
        // SEH dispatch mechanism).
        X86InstructionHelper::GeneratePopEaxOpCode(thunkBytes);
        X86InstructionHelper::GenerateJumpViaEaxOpCode(thunkBytes);

        memcpy(pCur, thunkBytes.data(), thunkBytes.size());

        DWORD oldProtection;
        if(!VirtualProtect(g_pThunkMem.get(), 
                           thunkMemSizeInBytes, 
                           PAGE_EXECUTE, 
                           &oldProtection))
        {
            res = GetLastError();
            printf("VirtualProtect Error: 0x%x\n", res);
        }

        return res;
    }

    // Walk the excetion registration chain rooted at fs:[0] extracting a 
    // pointer to the callback handler pointer from each record (to be used by 
    // PatchExceptionHandlerChain).
    template <typename TIter>
    void ExtractSEHHandlers(TIter out)
    {
        // The first SEH handler record is in the TIB at offset 0. Use the 
        // helper __readfsdword method to avoid having to fetch the value via 
        // inine assembly.
        void *pChainCurrent = reinterpret_cast<void*>(__readfsdword(0x0));

        while(pChainCurrent != EXCEPTION_CHAIN_END)
        {
            EXCEPTION_REGISTRATION_RECORD *pRegistration = reinterpret_cast<EXCEPTION_REGISTRATION_RECORD*>(pChainCurrent);
            *(out++) = &(pRegistration->Handler);

            pChainCurrent = pRegistration->Next;
        }
    }

    // A simple template that will expand to N instantiations of Intermediary 
    // via some template-meta programming (which normally is horrid, but I think 
    // this use is minimally mind-bending).
    template <int N>
    int Intermediary(vector<PEXCEPTION_ROUTINE*>& refVecHandlers)
    {
        __try
        {
            Intermediary<N-1>(refVecHandlers);
        }
        __except(EXCEPTION_CONTINUE_SEARCH)
        { }

        return 0;
    }

    // Recursion terminating template specialization so when N hits 0 we use this 
    // method which patches the SEH chain and generates an exception.
    template <>
    int Intermediary<0>(vector<PEXCEPTION_ROUTINE*>& refVecHandlers)
    {
        // Interesting thing to note here. In CHK builds this frame will 
        // register an SEH handler. Why? Because the STL has CHK iterators 
        // in debug mode (which I create via calling begin\end below on 
        // refVecHandlers) and they have dtors. So MSVC++ registers an SEH 
        // handler to ensure the dtor fires on unwind if the SEH exception 
        // is a C++ exception (or if we were compiling with /EHa).
        ExtractSEHHandlers(back_inserter(refVecHandlers));

        DWORD res = PatchExceptionHandlerChain(begin(refVecHandlers), 
                                               end(refVecHandlers));
        if(res != ERROR_SUCCESS)
        {
            printf("PatchExceptionHandlerChain Error: 0x%x\n", res);
            return res;
        }
        else
        {
            printf("Found and patched %d handlers!\n", refVecHandlers.size());

            // Time to trigger an exception :) This is done via a global volatile 
            // because the optimizer (in RET builds) was previously eliminating 
            // it.
            *globalNull = 0x424F4F4D;
        }

        return 0;
    }

    // Simple filter that prints a message before telling the OS it will handle 
    // the exception.
    DWORD ExceptionFilter()
    {
        printf("Telling the OS I will handle this exception inside IntermediaryBase\r\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    // The idea is to use some template-ry to generate some number of 
    // intermediate function call frames between here (the location with our 
    // 'catch and ignore all exceptions' handler) and the frame that will 
    // patch the SEH chain and generate our SEH exception.
    template <int IntermediaryDepth>
    int IntermediaryBase(vector<PEXCEPTION_ROUTINE*>& refVecHandlers)
    {
        // This handler is just a backstop before any auto-inserted ones (from 
        // the CRT or from Windows). If we let our null-ref exception reach them 
        // then we will not see the unwind behavior flowing through our thunks, 
        // and our process will die, so ... bad :)
        __try
        {
            return Intermediary<IntermediaryDepth>(refVecHandlers);
        }
        __except(ExceptionFilter())
        {
            printf("Exception ignored in IntermediaryBase\r\n");
        }

        return 0;
    }
}

int main(int argc, wchar_t* argv[])
{
    // Located here because you can't have C++ objects that contain dtors in 
    // the same method that you have explicit SEH handlers.
    vector<PEXCEPTION_ROUTINE*> registeredHandlers;

    // The template int param will indicate how many intermediary frames 
    // containing __try / __except(EXCEPTION_CONTINUE_SEARCH) are inserted 
    // between the base node (that will ignore the exception) and the leaf 
    // node, that will generate the exception.
    IntermediaryBase<10>(registeredHandlers);

    return 0;
}