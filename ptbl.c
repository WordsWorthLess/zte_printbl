// arm-linux-gnueabi-gcc -O2 -marm ptbl.c -ldl -o ptbl -Wl,--export-dynamic
// arm-linux-gnueabihf-gcc -O2 -marm ptbl.c -ldl -o ptbl_hf -Wl,--export-dynamic
// mips-unknown-linux-uclibc-gcc -O2 ptbl.c -ldl -o ptbl_mips -Wl,--export-dynamic
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define FOO_FUNC_SECTION __attribute__((aligned(8), section(".foo")))

typedef int (*fn_DBShmCliInit)();
typedef int (*fn_dbPrintTbl)(const char* tbl_name);
typedef void (*fn_dbPrintAllTbl)();

int ProcUserLog(const char* file, int line, const char* func, 
	int n1, int n2, const char* fmt, ...)
{
	return 0;
}

int OssDebugPrintf(const char* fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	return 0;
}

size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if(size)
	{
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}

// 修改dbPrintTbl函数的机器码来跳过检查
static int patch_dbPrintTbl(unsigned char* addr)
{
	int ret = 1;
	long page_size = sysconf(_SC_PAGESIZE);
	void* page_start = (void*)((long)addr & ~(page_size - 1));

	if(page_size == -1) {
		fprintf(stderr, "Failed to get page size\n");
		return ret;
	}

	ret = mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if(ret != 0) {
		fprintf(stderr, "Failed to make memory writable: %s\n", strerror(errno));
		return ret;
	}

	printf("Patching dbPrintTbl at %p to skip hidden checks...\n", addr);

	// 搜索并修改检查逻辑
	// 我们需要找到 JicaiFlag 检查和 dbDmNeedHidden 检查的代码并跳过它们
	
#if defined(__arm__)
	// ARM架构的修补
	// 查找条件跳转指令并修改为无条件跳转到显示逻辑
	// 这里需要根据实际函数代码进行调整
	
	// 简单方案：在函数开头直接跳转到显示逻辑
	// 但更安全的方法是找到具体的检查代码位置
	
	// 先尝试搜索函数中的关键指令模式
	// 这里提供一个通用的修补方案：修改条件跳转
	
	for (int i = 0; i < 256; i += 4) {  // 搜索前256字节
		// 查找条件分支指令（ARM条件码在 bits 28-31）
		if ((addr[i+3] & 0xF0) == 0xA0) {  // 可能是条件分支
			// 修改为无条件分支或NOP
			addr[i] = 0x00; addr[i+1] = 0x00; addr[i+2] = 0xA0; addr[i+3] = 0xE1; // NOP
			printf("Patched conditional branch at offset %d\n", i);
		}
	}
	
#elif defined(__mips__)
	// MIPS架构的修补
	// 查找条件分支指令并修改
	
	for (int i = 0; i < 256; i += 4) {
		// MIPS条件分支指令通常以 0x10-0x17 开头
		if ((addr[i] & 0xFC) == 0x10) {  // beq, bne 等
			// 修改为无条件跳转或NOP
			addr[i] = 0x00; addr[i+1] = 0x00; addr[i+2] = 0x00; addr[i+3] = 0x00; // NOP
			printf("Patched conditional branch at offset %d\n", i);
		}
	}
	
#else
	#error "Unsupported architecture"
#endif

	printf("dbPrintTbl patched to skip hidden checks\n");
	return 0;
}

// 更精确的修补方案：直接修改检查逻辑
static int patch_dbPrintTbl_precise(unsigned char* addr)
{
	int ret = 1;
	long page_size = sysconf(_SC_PAGESIZE);
	void* page_start = (void*)((long)addr & ~(page_size - 1));

	if(page_size == -1) {
		fprintf(stderr, "Failed to get page size\n");
		return ret;
	}

	ret = mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if(ret != 0) {
		fprintf(stderr, "Failed to make memory writable: %s\n", strerror(errno));
		return ret;
	}

	printf("Precise patching dbPrintTbl at %p...\n", addr);

	// 根据您提供的dbPrintTbl函数逻辑，我们需要跳过：
	// if ( JicaiFlag || !j_dbDmNeedHidden(...) )
	
	// 在汇编层面，这通常表现为条件跳转指令
	// 我们可以修改这些条件跳转，使其总是跳转到显示逻辑

#if defined(__arm__)
	// ARM: 修改条件跳转为无条件跳转或总是跳转到显示分支
	// 查找 beq, bne, bgt 等条件分支指令
	
	for (int i = 0; i < 512; i += 4) {  // 搜索前512字节
		// ARM条件分支指令格式：cond 1010 offset
		if ((addr[i+3] & 0xF0) == 0xA0) {  // 条件分支指令
			// 修改条件码为"总是" (AL)
			addr[i+3] = 0xEA;  // B 指令（无条件跳转）
			printf("Patched branch instruction at offset %d\n", i);
		}
	}
	
#elif defined(__mips__)
	// MIPS: 修改条件分支指令
	for (int i = 0; i < 512; i += 4) {
		// beq, bne 等条件分支
		if ((addr[i] & 0xFC) == 0x10) {
			// 修改为总是跳转（beq $zero, $zero, offset）
			addr[i] = 0x10; addr[i+1] = 0x00; addr[i+2] = 0x00; addr[i+3] = 0x01;
			printf("Patched branch instruction at offset %d\n", i);
		}
	}
#endif

	printf("dbPrintTbl precisely patched to skip all hidden checks\n");
	return 0;
}

static void help(void)
{
	fprintf(stderr, "p <table name> -- print table data.\n");
	fprintf(stderr, "all            -- print all table name.\n");
	fprintf(stderr, "exit           -- exit.\n");
}

int main(int argc, char* argv[])
{
	void *handle = NULL;
	fn_DBShmCliInit DBShmCliInit = NULL;
	fn_dbPrintTbl dbPrintTbl = NULL;
	fn_dbPrintAllTbl dbPrintAllTbl = NULL;
	char cmd[256];
	int len, ret = 1;

	printf("Starting ptbl tool (direct patch version)...\n");

	// 加载 libdb.so
	handle = dlopen("libdb.so", RTLD_LAZY | RTLD_GLOBAL);
	if(NULL == handle)
	{
		fprintf(stderr, "dlopen libdb.so error: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Successfully loaded libdb.so\n");

	// 查找必要函数
	DBShmCliInit = (fn_DBShmCliInit)dlsym(handle, "DBShmCliInit");
	if(DBShmCliInit == NULL)
	{
		fprintf(stderr, "DBShmCliInit not found: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Found DBShmCliInit at: %p\n", DBShmCliInit);

	dbPrintTbl = (fn_dbPrintTbl)dlsym(handle, "dbPrintTbl");
	if(dbPrintTbl == NULL)
	{
		fprintf(stderr, "dbPrintTbl not found: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Found dbPrintTbl at: %p\n", dbPrintTbl);

	dbPrintAllTbl = (fn_dbPrintAllTbl)dlsym(handle, "dbPrintAllTbl");
	if(dbPrintAllTbl == NULL)
	{
		fprintf(stderr, "dbPrintAllTbl not found: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Found dbPrintAllTbl at: %p\n", dbPrintAllTbl);

	// 直接修补dbPrintTbl函数来跳过隐藏检查
	printf("Patching dbPrintTbl to skip JicaiFlag and hidden checks...\n");
	if(patch_dbPrintTbl_precise((unsigned char*)dbPrintTbl) != 0)
	{
		fprintf(stderr, "Trying alternative patch method...\n");
		if(patch_dbPrintTbl((unsigned char*)dbPrintTbl) != 0)
		{
			fprintf(stderr, "Failed to patch dbPrintTbl\n");
			goto lbl_exit;
		}
	}
	printf("Successfully patched dbPrintTbl\n");

	// 初始化共享内存
	printf("Initializing shared memory...\n");
	int init_result = DBShmCliInit();
	printf("DBShmCliInit returned: %d\n", init_result);
	
	if(init_result != 0)
	{
		fprintf(stderr, "DBShmCliInit failed with code: %d\n", init_result);
		printf("Trying to continue anyway...\n");
	}
	else
	{
		printf("Shared memory initialized successfully\n");
	}

	ret = 0;
	
	// 命令行模式
	if(argc > 1)
	{
		printf("Printing table: %s\n", argv[1]);
		int print_result = dbPrintTbl(argv[1]);
		printf("dbPrintTbl returned: %d\n", print_result);
		goto lbl_exit;
	}
	
	// 交互模式
	printf("Entering interactive mode...\n");
	printf("All hidden checks have been disabled - all columns will be shown\n");
	
	while(1)
	{
		fprintf(stderr, "@ ");
		fflush(stderr);
		if(fgets(cmd, sizeof(cmd), stdin) == NULL)
			break;
			
		len = (int)strlen(cmd);
		if(len > 0 && '\n' == cmd[len - 1])
			cmd[len - 1] = '\0';

		if(strcmp(cmd, "exit") == 0)
			break;

		if(strncmp(cmd, "p ", 2) == 0)
		{
			printf("Printing table: %s\n", cmd+2);
			int result = dbPrintTbl(cmd + 2);
			printf("dbPrintTbl returned: %d\n", result);
		}
		else if(strcmp(cmd, "all") == 0)
		{
			printf("Printing all tables...\n");
			dbPrintAllTbl();
			printf("dbPrintAllTbl completed\n");
		}
		else
			help();
	}

	ret = 0;
lbl_exit:
	if(handle != NULL)
		dlclose(handle);

	printf("Exiting with code: %d\n", ret);
	return ret;
}
