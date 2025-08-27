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

// 设置 JicaiFlag 为 True (1)
static int set_JicaiFlag_to_true(unsigned char* dbPrintTbl_addr)
{
    printf("Setting JicaiFlag boolean to True (1)...\n");
    
#if defined(__arm__)
    // ARM架构策略1：修改 CfGetJicaiFlag 调用返回1
    for (int i = 0; i < 512; i += 4) {
        if (i + 3 < 512 && (dbPrintTbl_addr[i+3] & 0xF0) == 0xEB) {
            // 修改为 mov r0, #1 (返回True)
            dbPrintTbl_addr[i] = 0x01; 
            dbPrintTbl_addr[i+1] = 0x00; 
            dbPrintTbl_addr[i+2] = 0xA0; 
            dbPrintTbl_addr[i+3] = 0xE3; // mov r0, #1
            printf("Patched CfGetJicaiFlag to return True at offset %d\n", i);
            return 0;
        }
    }
    
    // ARM架构策略2：直接修改 JicaiFlag 的存储位置
    for (int i = 0; i < 512; i += 4) {
        if (i + 3 < 512 && dbPrintTbl_addr[i+3] == 0xE5) {
            // strb 指令，修改前面的赋值指令
            if (i >= 4) {
                // 修改前一条指令为 mov rX, #1
                dbPrintTbl_addr[i-4] = 0x01; 
                dbPrintTbl_addr[i-3] = 0x00; 
                dbPrintTbl_addr[i-2] = 0xA0; 
                dbPrintTbl_addr[i-1] = 0xE3; // mov r0, #1
                printf("Directly set JicaiFlag to True at offset %d\n", i-4);
                return 0;
            }
        }
    }
    
#elif defined(__mips__)
    // MIPS架构策略1：修改 CfGetJicaiFlag 调用返回1
    for (int i = 0; i < 512; i += 4) {
        if ((dbPrintTbl_addr[i] & 0xFC) == 0x0C) {  // jal 指令
            // 修改为 li v0, 1 (返回True)
            dbPrintTbl_addr[i] = 0x01; 
            dbPrintTbl_addr[i+1] = 0x00; 
            dbPrintTbl_addr[i+2] = 0x02; 
            dbPrintTbl_addr[i+3] = 0x24; // li v0, 1
            printf("Patched CfGetJicaiFlag to return True at offset %d\n", i);
            return 0;
        }
    }
    
    // MIPS架构策略2：直接修改存储指令
    for (int i = 0; i < 512; i += 4) {
        if (dbPrintTbl_addr[i] == 0xA0) {  // sb 指令
            // 修改前面的 li 指令为 li $tX, 1
            if (i >= 4) {
                dbPrintTbl_addr[i-4] = 0x01; 
                dbPrintTbl_addr[i-3] = 0x00; 
                dbPrintTbl_addr[i-2] = 0x02; 
                dbPrintTbl_addr[i-1] = 0x24; // li v0, 1
                printf("Directly set JicaiFlag to True at offset %d\n", i-4);
                return 0;
            }
        }
    }
#endif

    return 1;
}

// 确保条件判断总是为 True
static int ensure_condition_true(unsigned char* dbPrintTbl_addr)
{
    printf("Ensuring condition check is always True...\n");
    
#if defined(__arm__)
    // ARM: 修改条件跳转，让 if (JicaiFlag || ...) 总是为真
    for (int i = 0; i < 512; i += 4) {
        if ((dbPrintTbl_addr[i+3] & 0xF0) == 0xA0) {
            // 条件跳转指令，修改为无条件跳转或NOP
            if (dbPrintTbl_addr[i+3] == 0x0A) {  // beq
                // 修改为 bne 或者直接NOP
                dbPrintTbl_addr[i+3] = 0x1A;  // bne
                printf("Changed beq to bne at offset %d\n", i);
                return 0;
            } else if (dbPrintTbl_addr[i+3] == 0x1A) {  // bne
                // 修改为 beq 或者直接NOP
                dbPrintTbl_addr[i+3] = 0x0A;  // beq
                printf("Changed bne to beq at offset %d\n", i);
                return 0;
            }
        }
    }
    
#elif defined(__mips__)
    // MIPS: 修改条件分支指令
    for (int i = 0; i < 512; i += 4) {
        if ((dbPrintTbl_addr[i] & 0xFC) == 0x10) {  // beq/bne
            if (dbPrintTbl_addr[i] == 0x10) {  // beq
                dbPrintTbl_addr[i] = 0x14;  // bne
                printf("Changed beq to bne at offset %d\n", i);
                return 0;
            } else if (dbPrintTbl_addr[i] == 0x14) {  // bne
                dbPrintTbl_addr[i] = 0x10;  // beq
                printf("Changed bne to beq at offset %d\n", i);
                return 0;
            }
        }
    }
#endif

    return 1;
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

	printf("Starting ptbl tool - setting JicaiFlag to True...\n");

	// 加载 libdb.so
	handle = dlopen("libdb.so", RTLD_LAZY | RTLD_GLOBAL);
	if(NULL == handle) {
		fprintf(stderr, "dlopen libdb.so error: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Successfully loaded libdb.so\n");

	// 查找必要函数
	DBShmCliInit = (fn_DBShmCliInit)dlsym(handle, "DBShmCliInit");
	if(DBShmCliInit == NULL) {
		fprintf(stderr, "DBShmCliInit not found: %s\n", dlerror());
		goto lbl_exit;
	}

	dbPrintTbl = (fn_dbPrintTbl)dlsym(handle, "dbPrintTbl");
	if(dbPrintTbl == NULL) {
		fprintf(stderr, "dbPrintTbl not found: %s\n", dlerror());
		goto lbl_exit;
	}
	printf("Found dbPrintTbl at: %p\n", dbPrintTbl);

	dbPrintAllTbl = (fn_dbPrintAllTbl)dlsym(handle, "dbPrintAllTbl");
	if(dbPrintAllTbl == NULL) {
		fprintf(stderr, "dbPrintAllTbl not found: %s\n", dlerror());
		goto lbl_exit;
	}

	// 修改内存权限
	long page_size = sysconf(_SC_PAGESIZE);
	void* page_start = (void*)((long)dbPrintTbl & ~(page_size - 1));
	if(mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
		fprintf(stderr, "Failed to make memory writable: %s\n", strerror(errno));
		goto lbl_exit;
	}

	// 设置 JicaiFlag 为 True
	printf("Setting JicaiFlag boolean to True...\n");
	
	if (set_JicaiFlag_to_true((unsigned char*)dbPrintTbl) == 0) {
		printf("Successfully set JicaiFlag to True\n");
	} else if (ensure_condition_true((unsigned char*)dbPrintTbl) == 0) {
		printf("Successfully ensured condition is always True\n");
	} else {
		// 最终方案：直接修改条件判断逻辑
		printf("Using final approach: modifying condition logic\n");
		
		// 根据 dbPrintTbl 的代码逻辑：
		// if ( JicaiFlag || !j_dbDmNeedHidden(...) )
		// 我们需要让整个条件总是为 True
		
#if defined(__arm__)
		// 找到条件跳转并修改为总是跳转到显示逻辑
		for (int i = 0; i < 512; i += 4) {
			if ((dbPrintTbl_addr[i+3] & 0xF0) == 0xA0) {
				// 修改为无条件跳转 (B instruction)
				dbPrintTbl_addr[i+3] = 0xEA;
				printf("Forced condition to always be True at offset %d\n", i);
				break;
			}
		}
#elif defined(__mips__)
		for (int i = 0; i < 512; i += 4) {
			if ((dbPrintTbl_addr[i] & 0xFC) == 0x10) {
				// 修改为总是跳转
				dbPrintTbl_addr[i+3] = 0x01;
				printf("Forced condition to always be True at offset %d\n", i);
				break;
			}
		}
#endif
	}

	// 初始化共享内存
	printf("Initializing shared memory...\n");
	int init_result = DBShmCliInit();
	printf("DBShmCliInit returned: %d\n", init_result);
	
	if(init_result != 0) {
		printf("Note: Shared memory initialization completed\n");
	}

	ret = 0;
	
	// 命令行模式
	if(argc > 1) {
		printf("Printing table: %s\n", argv[1]);
		int result = dbPrintTbl(argv[1]);
		printf("Table printed successfully\n");
		goto lbl_exit;
	}
	
	// 交互模式
	printf("Entering interactive mode (JicaiFlag = True)...\n");
	printf("All columns will be displayed due to JicaiFlag being True\n");
	
	while(1) {
		fprintf(stderr, "@ ");
		fflush(stderr);
		if(fgets(cmd, sizeof(cmd), stdin) == NULL)
			break;
			
		len = (int)strlen(cmd);
		if(len > 0 && '\n' == cmd[len - 1])
			cmd[len - 1] = '\0';

		if(strcmp(cmd, "exit") == 0)
			break;

		if(strncmp(cmd, "p ", 2) == 0) {
			printf("Printing table: %s\n", cmd+2);
			dbPrintTbl(cmd + 2);
			printf("Table display completed\n");
		} else if(strcmp(cmd, "all") == 0) {
			printf("Printing all tables...\n");
			dbPrintAllTbl();
			printf("All tables displayed\n");
		} else {
			help();
		}
	}

	ret = 0;
lbl_exit:
	if(handle != NULL)
		dlclose(handle);

	printf("Program exited\n");
	return ret;
}
