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

// 简化版日志函数，避免使用高版本GLIBC特性
int ProcUserLog(const char* file, int line, const char* func, 
	int n1, int n2, const char* fmt, ...)
{
	return 0;
}

// 简化版调试输出
int OssDebugPrintf(const char* fmt, ...)
{
	va_list ap;
	char buffer[256];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (len > 0) {
		write(STDOUT_FILENO, buffer, len < sizeof(buffer) ? len : sizeof(buffer) - 1);
	}

	return 0;
}

// 安全的字符串拷贝函数
size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = 0;
	const char *s = src;

	if (size == 0) {
		while (*s++) ret++;
		return ret;
	}

	while (--size > 0 && *s) {
		*dest++ = *s++;
		ret++;
	}
	*dest = '\0';

	while (*s++) ret++;

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

// 改进的代码修改函数，支持多种架构
static int change_code(unsigned char* addr)
{
	int ret = 1;
	long page_size;
	void* page_start;
	unsigned char* new_code;
	ssize_t code_size;
	size_t i;

	// 获取系统页面大小
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		OssDebugPrintf("Failed to get page size\n");
		return ret;
	}

	page_start = (void*)((unsigned long)addr & ~(page_size - 1));

	// 计算函数大小
	new_code = (unsigned char*)&ret0;
	code_size = (char*)&ret0_0 - (char*)&ret0;
	if (code_size < 0) code_size = -code_size;

	// 限制代码大小，避免溢出
	if (code_size > 128) {
		OssDebugPrintf("Code size too large: %zd\n", code_size);
		return ret;
	}

	// 修改内存权限
	ret = mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (ret != 0) {
		OssDebugPrintf("Failed to make memory writable: %d\n", ret);
		return ret;
	}

	// 显示原始代码
	OssDebugPrintf("Patching function at %p, size: %zd\n", addr, code_size);

	// 复制新代码
	for (i = 0; i < code_size; i++) {
		addr[i] = new_code[i];
	}

	OssDebugPrintf("Function patched successfully\n");
	return 0;
}

static void help(void)
{
	const char* help_msg = 
		"p <table name> -- print table data.\n"
		"all            -- print all table name.\n"
		"exit           -- exit.\n";
	
	write(STDERR_FILENO, help_msg, strlen(help_msg));
}

// 安全的字符串比较函数
static int safe_strcmp(const char* s1, const char* s2)
{
	if (!s1 || !s2) return 1;
	while (*s1 && (*s1 == *s2)) {
		s1++;
		s2++;
	}
	return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// 安全的字符串拷贝到栈缓冲区
static void safe_strcpy(char* dest, const char* src, size_t dest_size)
{
	if (dest_size == 0) return;
	
	size_t i = 0;
	while (i < dest_size - 1 && src[i]) {
		dest[i] = src[i];
		i++;
	}
	dest[i] = '\0';
}

int main(int argc, char* argv[])
{
	void *handle = NULL;
	fn_DBShmCliInit DBShmCliInit = NULL;
	fn_dbDmNeedHidden dbDmNeedHidden = NULL;
	fn_dbPrintTbl dbPrintTbl = NULL;
	fn_dbPrintAllTbl dbPrintAllTbl = NULL;
	char cmd[256];
	int len, ret = 1;

	// 尝试加载libdb.so
	handle = dlopen("libdb.so", RTLD_LAZY);
	if (handle == NULL) {
		const char* error = dlerror();
		if (error) {
			OssDebugPrintf("dlopen error: %s\n", error);
		} else {
			OssDebugPrintf("dlopen error: unknown\n");
		}
		goto lbl_exit;
	}

	// 首先尝试查找 j_dbDmNeedHidden（跳板函数）
	dbDmNeedHidden = (fn_dbDmNeedHidden)dlsym(handle, "j_dbDmNeedHidden");
	if (dbDmNeedHidden == NULL) {
		// 如果找不到，尝试查找 dbDmNeedHidden
		dbDmNeedHidden = (fn_dbDmNeedHidden)dlsym(handle, "dbDmNeedHidden");
		if (dbDmNeedHidden == NULL) {
			OssDebugPrintf("Error: Neither j_dbDmNeedHidden nor dbDmNeedHidden found!\n");
			goto lbl_exit;
		}
	}

	// 查找其他必要函数
	DBShmCliInit = (fn_DBShmCliInit)dlsym(handle, "DBShmCliInit");
	dbPrintTbl = (fn_dbPrintTbl)dlsym(handle, "dbPrintTbl");
	dbPrintAllTbl = (fn_dbPrintAllTbl)dlsym(handle, "dbPrintAllTbl");

	if (DBShmCliInit == NULL || dbPrintTbl == NULL || dbPrintAllTbl == NULL) {
		OssDebugPrintf("Error: Required symbols not found!\n");
		OssDebugPrintf("DBShmCliInit: %p\n", DBShmCliInit);
		OssDebugPrintf("dbPrintTbl: %p\n", dbPrintTbl);
		OssDebugPrintf("dbPrintAllTbl: %p\n", dbPrintAllTbl);
		goto lbl_exit;
	}

	OssDebugPrintf("Found dbDmNeedHidden at: %p\n", dbDmNeedHidden);

	// 修补函数
	if (change_code((unsigned char*)dbDmNeedHidden) != 0) {
		OssDebugPrintf("Failed to patch dbDmNeedHidden\n");
		goto lbl_exit;
	}

	ret = 0;
	
	// 初始化共享内存
	if (DBShmCliInit() != 0) {
		OssDebugPrintf("DBShmCliInit failed\n");
		ret = 1;
		goto lbl_exit;
	}

	// 如果有命令行参数，直接执行并退出
	if (argc > 1) {
		dbPrintTbl(argv[1]);
		goto lbl_exit;
	}
	
	// 交互模式
	while (1) {
		const char* prompt = "@ ";
		write(STDERR_FILENO, prompt, strlen(prompt));
		
		if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
			break;
		}
		
		len = 0;
		while (len < sizeof(cmd) && cmd[len] != '\0') {
			if (cmd[len] == '\n') {
				cmd[len] = '\0';
				break;
			}
			len++;
		}

		if (safe_strcmp(cmd, "exit") == 0) {
			break;
		}

		if (safe_strcmp(cmd, "all") == 0) {
			dbPrintAllTbl();
		} else if (len >= 2 && cmd[0] == 'p' && cmd[1] == ' ') {
			OssDebugPrintf("table name: [%s]\n", cmd + 2);
			dbPrintTbl(cmd + 2);
		} else {
			help();
		}
	}

	ret = 0;
lbl_exit:
	if (handle != NULL) {
		dlclose(handle);
	}
	return ret;
}
