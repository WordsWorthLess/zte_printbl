// arm-linux-gnueabi-gcc -O2 -marm ptbl.c -ldl -o ptbl -Wl,--export-dynamic
// arm-linux-gnueabihf-gcc -O2 -marm ptbl.c -ldl -o ptbl_hf -Wl,--export-dynamic
// mips-unknown-linux-uclibc-gcc -O2 ptbl.c -ldl -o ptbl_mips -Wl,--export-dynamic
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>

#define FOO_FUNC_SECTION __attribute__((aligned(8), section(".foo")))

typedef int (*fn_DBShmCliInit)();
typedef int (*fn_dbDmNeedHidden)(const char* tbl_name, const char* col_name);
typedef int (*fn_dbPrintTbl)(const char* tbl_name);
typedef void (*fn_dbPrintAllTbl)();
typedef unsigned char (*fn_CfGetJicaiFlag)(); // 新增函数类型

int ProcUserLog(const char* file, int line, const char* func, 
	int n1, int n2, const char* fmt, ...)
{
	/*va_list ap;

	printf("[%s(%d)%s] ", file, line, func);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');*/

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

static int change_code(unsigned char* addr)
{
	int ret = 1;
	unsigned char* new_code;
	size_t code_size = 0, i;
	ssize_t tmp;
	long page_size = sysconf(_SC_PAGESIZE);
	void* page_start = (void*)((long)addr & ~(page_size - 1));

	new_code = (unsigned char*)&ret0;
	tmp = (char*)&ret0 - (char*)&ret0_0;
	code_size = tmp >= 0 ? tmp : -tmp;

	if(code_size > 64)
	{
		fprintf(stderr, "Code size error: %zu\n", code_size);
		return ret;
	}

	ret = mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if(0 == ret)
	{
		static const char* tab = "0123456789ABCDEF";
		char buf[256];

		for(i=0; i<code_size; i++)
		{
			buf[3 * i    ] = tab[addr[i] >> 4];
			buf[3 * i + 1] = tab[addr[i] & 0xF];
			buf[3 * i + 2] = ' ';
		}
		buf[3 * i] = '\0';
		printf("%p original code: %s\n", addr, buf);

		memcpy(addr, new_code, code_size);
		for(i=0; i<code_size; i++)
		{
			buf[3 * i    ] = tab[addr[i] >> 4];
			buf[3 * i + 1] = tab[addr[i] & 0xF];
			buf[3 * i + 2] = ' ';
		}
		buf[3 * i] = '\0';
		printf("%p      new code: %s\n", addr, buf);
	}
	else
		printf("Failed to make memory writable\n");

	return ret;
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
	fn_CfGetJicaiFlag CfGetJicaiFlag = NULL; // 新增函数指针
	char cmd[256];
	int len, ret = 1;

	// 首先尝试加载 libdb.so
	handle = dlopen("libdb.so", RTLD_LAZY);
	if(NULL == handle)
	{
		fprintf(stderr, "dlopen libdb.so error: %s\n", dlerror());
		goto lbl_exit;
	}

	// 尝试从其他库加载 CfGetJicaiFlag
	handle_other = dlopen(NULL, RTLD_LAZY); // 首先在当前进程查找
	if(handle_other != NULL)
	{
		CfGetJicaiFlag = (fn_CfGetJicaiFlag)dlsym(handle_other, "CfGetJicaiFlag");
		if(CfGetJicaiFlag == NULL)
		{
			// 尝试从其他常见库加载
			void *handle_cf = dlopen("libcf.so", RTLD_LAZY | RTLD_NOLOAD);
			if(handle_cf != NULL)
			{
				CfGetJicaiFlag = (fn_CfGetJicaiFlag)dlsym(handle_cf, "CfGetJicaiFlag");
				dlclose(handle_cf);
			}
		}
	}

	// 如果还是找不到，使用本地模拟函数
	if(CfGetJicaiFlag == NULL)
	{
		printf("CfGetJicaiFlag not found, using local implementation\n");
		CfGetJicaiFlag = local_CfGetJicaiFlag;
	}

	// 查找 libdb.so 中的函数
	DBShmCliInit = (fn_DBShmCliInit)dlsym(handle, "DBShmCliInit");
	
	// 首先尝试查找 j_dbDmNeedHidden（跳板函数）
	dbDmNeedHidden = (fn_dbDmNeedHidden)dlsym(handle, "j_dbDmNeedHidden");
	if(dbDmNeedHidden == NULL)
	{
		// 如果找不到，尝试查找 dbDmNeedHidden
		dbDmNeedHidden = (fn_dbDmNeedHidden)dlsym(handle, "dbDmNeedHidden");
		if(dbDmNeedHidden == NULL)
		{
			fprintf(stderr, "Error: Neither j_dbDmNeedHidden nor dbDmNeedHidden found!\n");
			goto lbl_exit;
		}
	}

	dbPrintTbl = (fn_dbPrintTbl)dlsym(handle, "dbPrintTbl");
	dbPrintAllTbl = (fn_dbPrintAllTbl)dlsym(handle, "dbPrintAllTbl");
	
	if(NULL == DBShmCliInit || NULL == dbPrintTbl || NULL == dbPrintAllTbl)
	{
		fprintf(stderr, "DBShmCliInit: %p\n", DBShmCliInit);
		fprintf(stderr, "dbPrintTbl: %p\n", dbPrintTbl);
		fprintf(stderr, "dbPrintAllTbl: %p\n", dbPrintAllTbl);
		fprintf(stderr, "Error!!! Symbol not found!\n");
		goto lbl_exit;
	}

	printf("Found dbDmNeedHidden at: %p\n", dbDmNeedHidden);
	printf("Found CfGetJicaiFlag at: %p\n", CfGetJicaiFlag);

	if(change_code((unsigned char*)dbDmNeedHidden) != 0)
		goto lbl_exit;

	ret = 0;
	if(DBShmCliInit() != 0)
	{
		fprintf(stderr, "DBShmCliInit failed\n");
		ret = 1;
		goto lbl_exit;
	}
	
	// 如果有命令行参数，直接打印表格内容并退出
	if(argc > 1)
	{
		printf("Printing table: %s\n", argv[1]);
		dbPrintTbl(argv[1]);
		goto lbl_exit;
	}
	
	// 交互模式
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
			printf("table name: [%s]\n", cmd+2);
			dbPrintTbl(cmd + 2);
		}
		else if(strcmp(cmd, "all") == 0)
			dbPrintAllTbl();
		else
			help();
	}

	ret = 0;
lbl_exit:
	if(handle_other != NULL)
		dlclose(handle_other);
	if(handle != NULL)
		dlclose(handle);

	return ret;
}
