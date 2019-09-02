#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>

static int g_poc_major = 0;
module_param(g_poc_major, int, 0);
MODULE_AUTHOR("Tiny");
MODULE_LICENSE("Dual BSD/GPL");

#define MAX_POC_DEV 2
static struct cdev g_PocDevs[MAX_POC_DEV];
dev_t g_dev;
struct class *g_pmy_class;

int g_page_order = 2;  //10 2M page 2 4k page 
unsigned long g_user_or_kenel_va = 0;
struct POC_ARG
{	
	unsigned long kerl_user_flag; //0 kernel va address; 1 user va address
	unsigned long out_kerl_va;
	unsigned long out_kerl_pa;
	unsigned long out_kerl_va_pte_va;
	unsigned long out_kerl_va_pte_value;
	unsigned long in_user_va;
	unsigned long out_user_pa;
	unsigned long out_user_va_pte_va;
	unsigned long out_user_va_pte_value;
};
#define IOCTL_CMD_PAGE_TABLE_WALK (0x100)
#define IOCTL_CMD_CLEAR_PAGE_PRESENT (0x200)
#define IOCTL_CMD_GET_PTE_OR_PDE_VALUE (0x300)
#define IOCTL_CMD_FLUSH_TLB_ONE (0x400)
#define IOCTL_CMD_SET_PAGE_PRESENT (0x500)

struct PAGE_TABLE_4K_ATTR
{
	unsigned long  va;
	unsigned long  pa;
	unsigned long  pml4va;
 	unsigned long  pdpteva;
	unsigned long  pdeva;
	unsigned long  pteva;
};

struct PAGE_TABLE_4K_ATTR g_user_page_table_4k_attr =
{
	.va = 0,
	.pa = 0,
	.pml4va = 0,
	.pdpteva = 0,
	.pdeva = 0,
	.pteva = 0,	
};
struct PAGE_TABLE_4K_ATTR g_kernel_page_table_4k_attr = 
{
	.va = 0,
	.pa = 0,
	.pml4va = 0,
	.pdpteva = 0,
	.pdeva = 0,
	.pteva = 0,	
};

int f_out_kernel_va_pa_and_pde(struct PAGE_TABLE_4K_ATTR *kernel_page_table_4k_attr)
{
	const unsigned long mask_51_12 = 0xfffffffff000ull;
	const unsigned long mask_pml4  = 0xff8000000000ull;
	const unsigned long mask_pdpt  = 0x007fc0000000ull;
	const unsigned long mask_pde   = 0x00003fe00000ull;
    const unsigned long mask_pte   = 0x0000001ff000ull;
	unsigned long va, pa;
	unsigned long pml4pa, pdptepa, pdepa, ptepa;
	unsigned long pml4entryvalue, pdpteentryvalue, pdeentryvalue, pteentryvalue;
	unsigned long cr3;
	unsigned long *vatmp;
	
	va = (unsigned long)__get_free_pages(GFP_USER, g_page_order);
	if(va == 0)
	{
		printk("__get_free_page is fail\n");
		return -1;
	}
	printk("va is 0x%lx\n", va);
	kernel_page_table_4k_attr->va = va;

	pa = (unsigned long)virt_to_phys((void*)va);
	printk("pa is 0x%lx\n", pa);
	kernel_page_table_4k_attr->pa = pa;

	cr3 = __read_cr3();
	printk("current process cr3 is 0x%lx\n", cr3);

	pml4pa = (cr3 & mask_51_12) + ((va & mask_pml4)>>39)*8;
	printk("pml4 entry pa is 0x%lx\n", pml4pa);
	vatmp = (unsigned long *) phys_to_virt((phys_addr_t)pml4pa);
	pml4entryvalue = *vatmp;
	*vatmp = pml4entryvalue | 0x7;
	pml4entryvalue = *vatmp;
	printk("pml4 entry va is 0x%lx\n", vatmp);
	printk("pml4 entry value is 0x%lx\n", pml4entryvalue);
	kernel_page_table_4k_attr->pml4va = vatmp;

	pdptepa = (pml4entryvalue & mask_51_12) + ((va & mask_pdpt)>>30)*8;
	printk("pdpte entry pa is 0x%lx\n", pdptepa);
	vatmp = (unsigned long *)phys_to_virt((phys_addr_t)pdptepa);
	pdpteentryvalue = *vatmp;
	*vatmp = pdpteentryvalue | 0x07;
	pdpteentryvalue = *vatmp;
	printk("pdpte entry va is 0x%lx\n", vatmp);
	printk("pdpte entry value is 0x%lx\n", pdpteentryvalue);
	kernel_page_table_4k_attr->pdpteva = vatmp;

	pdepa = (pdpteentryvalue & mask_51_12) + ((va & mask_pde)>>21)*8;
	printk("pde entry pa is 0x%lx\n",pdepa);
	vatmp = (unsigned long *)phys_to_virt((phys_addr_t)pdepa);
	pdeentryvalue = *vatmp;
	*vatmp = pdeentryvalue | 0x07;
	pdeentryvalue = *vatmp;
	printk("pde entry va is 0x%lx\n", vatmp);
	printk("pde entry value is 0x%lx\n", pdeentryvalue);
	if(pdeentryvalue & (1 << 7))
	{
		printk("the page size is 2M\n");
		kernel_page_table_4k_attr->pdeva = vatmp;
	}
	else
	{
		printk("the page size is 4k\n");
		ptepa = (pdeentryvalue & mask_51_12) + ((va & mask_pte)>>12)*8;
		printk("pte entry pa is 0x%lx\n", ptepa);
		vatmp = (unsigned long *)phys_to_virt((phys_addr_t)ptepa);
		pteentryvalue = *vatmp;
		*vatmp = pteentryvalue | 0x7;
		pteentryvalue = *vatmp;
		printk("pte entry va is 0x%lx\n", vatmp);
		printk("pte entry value is 0x%lx\n", pteentryvalue);
		kernel_page_table_4k_attr->pteva = vatmp;
	}
	return 0;
}

int f_in_user_va_get_pde(unsigned long inva, struct PAGE_TABLE_4K_ATTR *user_page_table_4k_attr)
{
	const unsigned long mask_51_12 = 0xfffffffff000ull;
	const unsigned long mask_pml4  = 0xff8000000000ull;
	const unsigned long mask_pdpt  = 0x007fc0000000ull;
	const unsigned long mask_pde   = 0x00003fe00000ull;
    const unsigned long mask_pte   = 0x0000001ff000ull;
	unsigned long va, pa;
	unsigned long pml4pa, pdptepa, pdepa, ptepa;
	unsigned long pml4entryvalue, pdpteentryvalue, pdeentryvalue, pteentryvalue;
	unsigned long cr3;
	unsigned long *vatmp;
	
	va = inva;
	printk("input va is 0x%lx\n", va);
	user_page_table_4k_attr->va = va;
	pa = (unsigned long)virt_to_phys((void*)va);
	printk("pa is 0x%lx\n", pa);
	user_page_table_4k_attr->pa = pa;

	cr3 = __read_cr3();
	printk("current process cr3 is 0x%lx\n", cr3);

	pml4pa = (cr3 & mask_51_12) + ((va & mask_pml4)>>39)*8;
	printk("pml4 entry pa is 0x%lx\n", pml4pa);
	vatmp = (unsigned long *) phys_to_virt((phys_addr_t)pml4pa);
	pml4entryvalue = *vatmp;
	*vatmp = pml4entryvalue | 0x7;
	pml4entryvalue = *vatmp;
	printk("pml4 entry va is 0x%lx\n", vatmp);
	printk("pml4 entry value is 0x%lx\n", pml4entryvalue);
	user_page_table_4k_attr->pml4va = vatmp;

	pdptepa = (pml4entryvalue & mask_51_12) + ((va & mask_pdpt)>>30)*8;
	printk("pdpte entry pa is 0x%lx\n", pdptepa);
	vatmp = (unsigned long *)phys_to_virt((phys_addr_t)pdptepa);
	pdpteentryvalue = *vatmp;
	*vatmp = pdpteentryvalue | 0x07;
	pdpteentryvalue = *vatmp;
	printk("pdpte entry va is 0x%lx\n", vatmp);
	printk("pdpte entry value is 0x%lx\n", pdpteentryvalue);
	user_page_table_4k_attr->pdpteva = vatmp;

	pdepa = (pdpteentryvalue & mask_51_12) + ((va & mask_pde)>>21)*8;
	printk("pde entry pa is 0x%lx\n",pdepa);
	vatmp = (unsigned long *)phys_to_virt((phys_addr_t)pdepa);
	pdeentryvalue = *vatmp;
	*vatmp = pdeentryvalue | 0x07;
	pdeentryvalue = *vatmp;
	printk("pde entry va is 0x%lx\n", vatmp);
	printk("pde entry value is 0x%lx\n", pdeentryvalue);
	if(pdeentryvalue & (1 << 7))
	{
		printk("the page size is 2M\n");
		user_page_table_4k_attr->pdeva = vatmp;
	}
	else
	{
		printk("the page size is 4k\n");
		ptepa = (pdeentryvalue & mask_51_12) + ((va & mask_pte)>>12)*8;
		printk("pte entry pa is 0x%lx\n", ptepa);
		vatmp = (unsigned long *)phys_to_virt((phys_addr_t)ptepa);
		pteentryvalue = *vatmp;
		*vatmp = pteentryvalue | 0x7; //  | 0x10 pcd set 1
		pteentryvalue = *vatmp;
		printk("pte entry va is 0x%lx\n", vatmp);
		printk("pte entry value is 0x%lx\n", pteentryvalue);
		user_page_table_4k_attr->pteva = vatmp;
	}	
	return 0;
}

void f_flush_tlb_one(unsigned long va)
{
	__asm__ __volatile__("invlpg (%0)" ::"r"(va):"memory");
}
static int f_poc_open(struct inode *pinode, struct file *pfile)
{
	printk("here is open\n");
	return 0;
}

static int f_poc_release(struct inode *pinode, struct file *pfile)
{
	printk("here is release\n");
	if(g_user_or_kenel_va == 0)
	{
		free_pages(g_kernel_page_table_4k_attr.va, g_page_order);
	}
	return 0;
}

static void f_poc_setup_cdev(struct cdev *pdev, int minor, struct file_operations *pfops)
{
	int err, devno = MKDEV(g_poc_major, minor);
	cdev_init(pdev,pfops);
	pdev->owner = THIS_MODULE;
	pdev->ops = pfops;
	err = cdev_add(pdev, devno, 1);
	if(err)
		printk(KERN_NOTICE "Error %d adding poc%d", err, minor);
}

long f_poc_ioctl(struct file *pfile, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct POC_ARG pocarg;
	if(copy_from_user(&pocarg,(void __user *)arg, sizeof(struct POC_ARG)))
		return ret;
	g_user_or_kenel_va = pocarg.kerl_user_flag;
	switch(cmd)
	{
		case IOCTL_CMD_PAGE_TABLE_WALK:
		{
			if(g_user_or_kenel_va == 0)
			{
				f_out_kernel_va_pa_and_pde(&g_kernel_page_table_4k_attr);
				pocarg.out_kerl_va = g_kernel_page_table_4k_attr.va;
				pocarg.out_kerl_pa = g_kernel_page_table_4k_attr.pa;
				pocarg.out_kerl_va_pte_va = g_kernel_page_table_4k_attr.pteva;
				pocarg.out_kerl_va_pte_value = *((unsigned long *)g_kernel_page_table_4k_attr.pteva);
			}
			else if(g_user_or_kenel_va == 1)
			{
				f_in_user_va_get_pde(pocarg.in_user_va, &g_user_page_table_4k_attr);
				pocarg.out_user_pa = g_user_page_table_4k_attr.pa;
				pocarg.out_user_va_pte_va = g_user_page_table_4k_attr.pteva;
				pocarg.out_user_va_pte_value = *((unsigned long *)g_user_page_table_4k_attr.pteva);	
			}
			else
			{
				printk("invalid va\n");
			}
			printk("cmd table walk\n");
		}
		break;
		case IOCTL_CMD_CLEAR_PAGE_PRESENT:
		{
			if(g_user_or_kenel_va == 0)
			{
				printk("pte entry value befer is 0x%lx\n", *((unsigned long *)g_kernel_page_table_4k_attr.pteva));
				*((unsigned long *)g_kernel_page_table_4k_attr.pteva) = (*((unsigned long *)g_kernel_page_table_4k_attr.pteva)) & (~0x1);
				__flush_tlb_all();
				printk("pte entry value after is 0x%lx\n", *((unsigned long *)g_kernel_page_table_4k_attr.pteva));
			}
			else if(g_user_or_kenel_va == 1)
			{
				//__flush_tlb_all();
				//f_flush_tlb_one(g_user_page_va);			
				//printk("pte entry value befer is 0x%lx\n", *((unsigned long *)g_user_page_table_4k_attr.pteva));

				*((unsigned long *)g_user_page_table_4k_attr.pteva) = (*((unsigned long *)g_user_page_table_4k_attr.pteva)) & (~0x1);
				//printk("pte entry value after is 0x%lx\n", *((unsigned long *)g_user_page_table_4k_attr.pteva));
			}
			else
			{
				printk("invalid va\n");
			}
			printk("cmd clear page p\n");
		}
		break;
		case IOCTL_CMD_SET_PAGE_PRESENT:
		{
			if(g_user_or_kenel_va == 0)
			{
				printk("pte entry value befer is 0x%lx\n", *((unsigned long *)g_kernel_page_table_4k_attr.pteva));
				*((unsigned long *)g_kernel_page_table_4k_attr.pteva) = (*((unsigned long *)g_kernel_page_table_4k_attr.pteva)) | (0x1);
				__flush_tlb_all();
				printk("pte entry value after is 0x%lx\n", *((unsigned long *)g_kernel_page_table_4k_attr.pteva));
			}
			else if(g_user_or_kenel_va == 1)
			{
				//__flush_tlb_all();
				//f_flush_tlb_one(g_user_page_va);			
				//printk("pte entry value befer is 0x%lx\n", *((unsigned long *)g_user_page_table_4k_attr.pteva));
				*((unsigned long *)g_user_page_table_4k_attr.pteva) = (*((unsigned long *)g_user_page_table_4k_attr.pteva)) | (0x1);
				//printk("pte entry value after is 0x%lx\n", *((unsigned long *)g_user_page_table_4k_attr.pteva));
			}
			else
			{
				printk("invalid va\n");
			}
			printk("cmd set page p");
		}
		break;
		case IOCTL_CMD_GET_PTE_OR_PDE_VALUE:
		{
			if(g_user_or_kenel_va == 0)
			{
				printk("last pte entry is 0x%lx\n", *((unsigned long *)g_kernel_page_table_4k_attr.pteva));
			}
			else if(g_user_or_kenel_va == 1)
			{
				printk("last pte entry is 0x%lx\n", *((unsigned long *)g_user_page_table_4k_attr.pteva));
			}
			else
			{
				printk("invalid va\n");
			}
		}
		break;
		case IOCTL_CMD_FLUSH_TLB_ONE:
		{
			if(g_user_or_kenel_va == 0)
			{
				f_flush_tlb_one(g_kernel_page_table_4k_attr.va);
			}
			else if(g_user_or_kenel_va == 1)
			{
				f_flush_tlb_one(g_user_page_table_4k_attr.va);
			}
			else
			{
				printk("invalid flush tlb \n");
			}
			printk("cmd flush tlb one\n");
		}
		default:
		break;
	}
	if(copy_to_user((void __user *)arg, &pocarg, sizeof(struct POC_ARG)))
		return ret;
	return ret;
}

static struct file_operations g_poc_remap_ops = {
	.owner = THIS_MODULE,
	.open = f_poc_open,
	.release = f_poc_release,
	.unlocked_ioctl = f_poc_ioctl,
	.compat_ioctl = f_poc_ioctl,
};

static int f_poc_init(void)
{
	int result;
	g_dev = MKDEV(g_poc_major,0);
	if(g_poc_major)
		result = register_chrdev_region(g_dev,2,"poc");
	else
	{
		result = alloc_chrdev_region(&g_dev, 0,2,"poc");
		g_poc_major = MAJOR(g_dev);
	}
	if(result < 0)
	{
		printk(KERN_WARNING "poc: unable to get major %d\n", g_poc_major);
		return result;
	}
	if(g_poc_major == 0)
		g_poc_major = result;
	g_pmy_class = class_create(THIS_MODULE, "poc_class");
	f_poc_setup_cdev(g_PocDevs, 0, &g_poc_remap_ops);
	device_create(g_pmy_class, NULL, g_dev, NULL, "poc");
	return 0;
}

static void f_poc_exit(void)
{
	cdev_del(g_PocDevs);
	device_destroy(g_pmy_class, g_dev);
	class_destroy(g_pmy_class);
	unregister_chrdev_region(MKDEV(g_poc_major,0), 2);
}

module_init(f_poc_init);
module_exit(f_poc_exit);

