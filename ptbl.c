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
typedef int (*fn_dbDmNeedHidden)(const char* tbl_name, const char* col_name);
typedef int (*fn_dbPrintTbl)(const char* tbl_name);
typedef void (*fn_dbPrintAllTbl)();
typedef unsigned char (*fn_CfGetJicaiFlag)();

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

FOO_FUNC_SECTION static int ret0(const char* tbl_name, const char* col_name)
{
	return 0;
}

FOO_FUNC_SECTION static int ret0_0(const char* tbl_name, const char* col_name)
{
	return 0;
}

// 新的修补函数，专门针对 j_dbDmNeedHidden
static int patch_j_dbDmNeedHidden(unsigned char* addr)
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

	// 根据不同架构生成直接返回0的代码
#if defined(__arm__)
	// ARM: mov r0, #0; bx lr (返回0)
	addr[0] = 0x00; addr[1] = 0x00; addr[2] = 0xA0; addr[3] = 0xE3; // mov r0, #0
	addr[4] = 0x1E; addr[5] = 0xFF; addr[6] = 0x2F; addr[7] = 0xE1; // bx lr
	// 用NOP填充剩余空间（如果需要）
	for(int i = 8; i < 16; i++) addr[i] = 0x00;
	
#elif defined(__mips__)
	// MIPS: li v0, 0; jr ra; nop (返回0)
	addr[0] = 0x00; addr[1] = 0x00; addr[2] = 0x02; addr[3] = 0x24; // li v0, 0
	addr[4] = 0x08; addr[5] = 0x00; addr[6] = 0xE0; addr[7] = 0x03; // jr ra
	addr[8] = 0x00; addr[9] = 0x00; addr[10] = 0x00; addr[11] = 0x00; // nop
	// 用NOP填充剩余空间
	for(int i = 12; i < 16; i++) addr[i] = 0x00;
	
#else
	#error "Unsupported architecture"
#endif

	// 显示修补信息
	printf("Patched j_dbDmNeedHidden at %p to always return false\n", addr);
	
	// 显示修补前后的代码
	printf("Patched code: ");
	for(int i = 0; i < 8; i++) {
		printf("%02X ", addr[i]);
	}
	printf("\n");
	
	return 0;
}

static void help(void)
{
	fprintf(stderr, "p <table name> -- print table data.\n");
	fprintf(stderr, "all            -- print all table name.\n");
	fprintf(stderr, "exit           -- exit.\n");
}

// 模拟 CfGetJicaiFlag 函数，总是返回 0
static unsigned char local_CfGetJicaiFlag(void)
{
    return 0;
}

int main(int argc, char* argv[])
{
	void *handle = NULL;
	void *handle_other = NULL;
	fn_DBShmCliInit DBShmCliInit = NULL;
	fn_dbDmNeedHidden dbDmNeedHidden = NULL;
	fn_dbPrintTbl dbPrintTbl = NULL;
	fn_dbPrintAllTbl dbPrintAllTbl = NULL;
	fn_CfGetJicaiFlag CfGetJicaiFlag = NULL;
	char cmd[256];
	int len, ret = 1;

	printf("Starting ptbl tool...\n");

	// 首先尝试加载 libdb.so
	handle = dlopen("libdb.so", RTLD_LAZY | RTLD_GLOBAL);
	if(NULL == handle)
	{
		fprintf(stderr, "dlopen libdb.so error: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Successfully loaded libdb.so\n");

	// 查找所有必要的函数
	DBShmCliInit = (fn_DBShmCliInit)dlsym(handle, "DBShmCliInit");
	if(DBShmCliInit == NULL)
	{
		fprintf(stderr, "DBShmCliInit not found: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Found DBShmCliInit at: %p\n", DBShmCliInit);
	
	// 优先查找 j_dbDmNeedHidden（跳板函数）
	dbDmNeedHidden = (fn_dbDmNeedHidden)dlsym(handle, "j_dbDmNeedHidden");
	if(dbDmNeedHidden == NULL)
	{
		// 如果找不到，尝试查找 dbDmNeedHidden
		dbDmNeedHidden = (fn_dbDmNeedHidden)dlsym(handle, "dbDmNeedHidden");
		if(dbDmNeedHidden == NULL)
		{
			fprintf(stderr, "Error: Neither j_dbDmNeedHidden nor dbDmNeedHidden found: %s\n", dlerror());
			goto lbl_exit;
		}
		printf("Found dbDmNeedHidden at: %p (will patch this instead)\n", dbDmNeedHidden);
	}
	else
	{
		printf("Found j_dbDmNeedHidden at: %p (will patch this)\n", dbDmNeedHidden);
	}

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

	// 尝试查找 CfGetJicaiFlag
	handle_other = dlopen(NULL, RTLD_LAZY);
	if(handle_other != NULL)
	{
		CfGetJicaiFlag = (fn_CfGetJicaiFlag)dlsym(handle_other, "CfGetJicaiFlag");
		if(CfGetJicaiFlag == NULL)
		{
			// 尝试从其他常见库加载
			const char* possible_libs[] = {
				"libcf.so", "libcf.so.1", "libcommon.so", "libshare.so", 
				"libsystem.so", "liboss.so", NULL
			};

			for(int i = 0; possible_libs[i] != NULL; i++) {
				void *handle_tmp = dlopen(possible_libs[i], RTLD_LAZY | RTLD_NOLOAD);
				if(handle_tmp != NULL) {
					CfGetJicaiFlag = (fn_CfGetJicaiFlag)dlsym(handle_tmp, "CfGetJicaiFlag");
					if(CfGetJicaiFlag != NULL) {
						printf("Found CfGetJicaiFlag in %s at: %p\n", possible_libs[i], CfGetJicaiFlag);
						dlclose(handle_tmp);
						break;
					}
					dlclose(handle_tmp);
				}
			}
		}
	}

	// 如果还是找不到，使用本地模拟函数
	if(CfGetJicaiFlag == NULL)
	{
		printf("CfGetJicaiFlag not found, using local implementation at: %p\n", local_CfGetJicaiFlag);
		CfGetJicaiFlag = local_CfGetJicaiFlag;
	}

	// 修补 j_dbDmNeedHidden 或 dbDmNeedHidden
	printf("Patching function to always return false...\n");
	if(patch_j_dbDmNeedHidden((unsigned char*)dbDmNeedHidden) != 0)
	{
		fprintf(stderr, "Failed to patch the function\n");
		goto lbl_exit;
	}
	printf("Successfully patched the function\n");

	// 尝试初始化共享内存
	printf("Initializing shared memory...\n");
	int init_result = DBShmCliInit();
	printf("DBShmCliInit returned: %d\n", init_result);
	
	if(init_result != 0)
	{
		fprintf(stderr, "DBShmCliInit failed with code: %d\n", init_result);
		fprintf(stderr, "Error: %s\n", strerror(errno));
		printf("Warning: Trying to continue despite initialization failure...\n");
	}
	else
	{
		printf("Shared memory initialized successfully\n");
	}

	ret = 0;
	
	// 如果有命令行参数，直接打印表格内容并退出
	if(argc > 1)
	{
		printf("Printing table: %s\n", argv[1]);
		int print_result = dbPrintTbl(argv[1]);
		printf("dbPrintTbl returned: %d\n", print_result);
		goto lbl_exit;
	}
	
	// 交互模式
	printf("Entering interactive mode...\n");
	printf("Type 'p <table_name>' to print a table, 'all' to print all tables, 'exit' to quit\n");
	
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
	if(handle_other != NULL)
		dlclose(handle_other);
	if(handle != NULL)
		dlclose(handle);

	printf("Exiting with code: %d\n", ret);
	return ret;
}
