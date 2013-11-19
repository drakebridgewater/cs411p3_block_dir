/*
* Filename: encrypted_ramdisk.c
*
* Authors: Group 14 
*
* Based on examples from Linux Driver Development 3rd Edition. (ch 16)
* By Jonathan Corbet, Alessandro Rubini, Greg Kroah-Hartman. We also
* recieved assistance from Jordan Bayles. 
*
*
*/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/timer.h>
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/hdreg.h>	/* HDIO_GETGEO */
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* invalidate_bdev */
#include <linux/bio.h>

#include <linux/crypto.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR
    ("");
MODULE_DESCRIPTION
    ("Ramdisk device driver that uses crypto for encryption/decription as you read and write");


/*
 * The different "request modes" we can use.
 */
enum {
	RM_SIMPLE  = 0,	/* The extra-simple request function */
	RM_FULL    = 1,	/* The full-blown version */
	RM_NOQUEUE = 2,	/* Use make_request */
};

/*
 * Minor number and partition management.
 */
#define ENCRYPTED_RAMDISK_MINORS	16
#define MINOR_SHIFT	4
#define DEVNUM(kdevnum)	(MINOR(kdev_t_to_nr(kdevnum)) >> MINOR_SHIFT

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE	512

/*
 * After this much idle time, the driver will simulate a media change.
 */
#define INVALIDATE_DELAY	30*HZ

/*
 * The internal representation of our device.
 */
struct encrypted_ramdisk_dev {
        int size;                       /* Device size in sectors */
        u8 *data;                       /* The data array */
        short users;                    /* How many users */
        short media_change;             /* Flag a media change? */
        spinlock_t lock;                /* For mutual exclusion */
        struct request_queue *queue;    /* The device request queue */
        struct gendisk *gd;             /* The gendisk structure */
        struct timer_list timer;        /* For simulated media changes */
};


static int encrypted_ramdisk_major = 0;
module_param(encrypted_ramdisk_major, int, 0);
MODULE_PARM_DESC(encrypted_ramdisk_major, "Major number, kernel can allocate");

static int hardsect_size = 512;
module_param(hardsect_size, int, 0);
MODULE_PARM_DESC(hardsect_size, "Sector size");

static int nsectors = 1024; /* How big the drive is */
module_param(nsectors, int, 0);
MODULE_PARM_DESC(nsectors, "Number of sectors");

static int ndevices = 4;
module_param(ndevices, int, 0);
MODULE_PARM_DESC(ndevices, "Number of devices");

static int request_mode = RM_SIMPLE;
module_param(request_mode, int, 0);
MODULE_PARM_DESC(request_mode, "Request mode");

static int encrypt = 1;
module_param(encrypt, int, 0);
MODULE_PARM_DESC(encrypt, "Encryption enabled");

static char *key = "defaultENCRYPTIONkey733t157";
module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "Encryption key");

static struct encrypted_ramdisk_dev *devices = NULL;

struct crypto_cipher *cipher = NULL;


/*
 * Handle an I/O request.
 */
static void 
encrypted_ramdisk_transfer(struct encrypted_ramdisk_dev *dev, 
        unsigned long sector, unsigned long nsect, char *buffer, int write)
{
	long i, loop_inc;
	unsigned long offset = sector*KERNEL_SECTOR_SIZE;
	unsigned long nbytes = nsect*KERNEL_SECTOR_SIZE;

	if ((offset + nbytes) > dev->size) {
		printk (KERN_NOTICE "(ENCRYPTED_RAMDISK) Beyond-end write (%ld %ld)\n", offset, nbytes);
		return;
	}
	
	if (write) {
	    printk("(ENCRYPTED_RAMDISK) Writing to ramdisk");
	    
	    /*encrypt is a bool determining weather it is encrypted or not*/
	    if (encrypt) {
	        loop_inc = crypto_cipher_blocksize(cipher);
	        for(i = 0; i < nbytes; i+=loop_inc){
	            /*clear the data that we are going to write over*/
	            memset(dev->data + offset + i, 0,
	                crypto_cipher_blocksize(cipher));

                printk("(ENCRYPTED_RAMDISK) i=%ld ",i);
                crypto_cipher_encrypt_one(cipher, dev->data + offset,
                    &buffer[i]);
	        }
	        return;
	    } else {
	        memcpy(dev->data + offset, buffer, nbytes);    
	        return;
	    }
	    printk("(ENCRYPTED_RAMDISK) Writing to ramdisk complete");
	}
	else {
	    printk("(ENCRYPTED_RAMDISK) Reading from ramdisk");
	    
	    /*encrypt is a bool determining weather it is encrypted or not*/
	    if (encrypt) {
	        loop_inc = crypto_cipher_blocksize(cipher);
	        for(i = 0; i < nbytes; i+=loop_inc){
                crypto_cipher_decrypt_one(cipher, &buffer[i], 
                    dev->data + offset + i );
	        }
	        return;
	    } else {
	        memcpy(buffer, dev->data + offset, nbytes);   
	        return;
	    }
	    printk("(ENCRYPTED_RAMDISK) Read from ramdisk complete");
	}
}

/*
 * The simple form of the request function.
 */
static void 
encrypted_ramdisk_request(struct request_queue *q)
{
	struct request *req;
	
	req = blk_fetch_request(q);
	while (req != NULL) {
		struct encrypted_ramdisk_dev *dev = req->rq_disk->private_data;
		if ( (req)->cmd_type != REQ_TYPE_FS ) {
			printk (KERN_NOTICE "(ENCRYPTED_RAMDISK) Skip non-fs request\n");
			blk_end_request_cur(req, 0);
			continue;
		}
    //    	printk (KERN_NOTICE "(ENCRYPTED_RAMDISK) Req dev %d dir %ld sec %ld, nr %d f %lx\n",
    //    			dev - Devices, rq_data_dir(req),
    //    			req->sector, req->current_nr_sectors,
    //    			req->flags);
		encrypted_ramdisk_transfer(dev, blk_rq_pos(req), blk_rq_cur_sectors(req),
				req->buffer, rq_data_dir(req));
		blk_end_request_cur(req, 1);
	}
}


/*
 * Transfer a single BIO.
 */
static int 
encrypted_ramdisk_xfer_bio(struct encrypted_ramdisk_dev *dev, struct bio *bio)
{
	int i;
	struct bio_vec *bvec;
	sector_t sector = bio->bi_sector;

	/* Do each segment independently. */
	bio_for_each_segment(bvec, bio, i) {
		char *buffer = __bio_kmap_atomic(bio, i, KM_USER0);
		encrypted_ramdisk_transfer(dev, sector,	bio_cur_bytes(bio) >> 9,
				buffer, bio_data_dir(bio) == WRITE);
		sector += bio_cur_bytes(bio) >> 9;
		__bio_kunmap_atomic(bio, KM_USER0);
	}
	return 0; /* Always "succeed" */
}

/*
 * Transfer a full request.
 */
static int 
encrypted_ramdisk_xfer_request(struct encrypted_ramdisk_dev *dev, struct request *req)
{
	struct bio *bio;
	int nsect = 0;
   	
	__rq_for_each_bio(bio, req); 
	
	encrypted_ramdisk_xfer_bio(dev, bio);
	nsect += bio->bi_size/KERNEL_SECTOR_SIZE;
	
	return nsect;
}



/*
 * Smarter request function that "handles clustering".
 */
static void 
encrypted_ramdisk_full_request(struct request_queue *q)
{
	struct request *req;
	int sectors_xferred;
	struct encrypted_ramdisk_dev *dev = q->queuedata;

	while ((req = blk_fetch_request(q)) != NULL) {
		if (! (req)->cmd_type != REQ_TYPE_FS) {
			printk (KERN_NOTICE "(ENCRYPTED_RAMDISK) Skip non-fs request\n");
			blk_end_request_cur(req, 0);
			continue;
		}
		sectors_xferred = encrypted_ramdisk_xfer_request(dev, req);
		if (! end_that_request_first(req, 1, sectors_xferred)) {
			blkdev_dequeue_request(req);
			end_that_request_last(req);
		}
	}
}



/*
 * The direct make request version.
 */
static int 
encrypted_ramdisk_make_request(request_queue_t *q, struct bio *bio)
{
	struct encrypted_ramdisk_dev *dev = q->queuedata;
	int status;

	status = encrypted_ramdisk_xfer_bio(dev, bio);
	bio_endio(bio, bio->bi_size, status);
	return 0;
}


/*
 * Open and close.
 */

static int 
encrypted_ramdisk_open(struct block_device *device, struct file *filp)
{
	struct encrypted_ramdisk_dev *dev = device->i_bdev->bd_disk->private_data;

	del_timer_sync(&dev->timer);
	filp->private_data = dev;
	spin_lock(&dev->lock);
	if (! dev->users) 
		check_disk_change(device->i_bdev);
	dev->users++;
	spin_unlock(&dev->lock);
	return 0;
}

static int 
encrypted_ramdisk_release(struct gendisk *disk, struct file *filp)
{
	struct encrypted_ramdisk_dev *dev = disk->i_bdev->bd_disk->private_data;

	spin_lock(&dev->lock);
	dev->users--;

	if (!dev->users) {
		dev->timer.expires = jiffies + INVALIDATE_DELAY;
		add_timer(&dev->timer);
	}
	spin_unlock(&dev->lock);

	return 0;
}

/*
 * Look for a (simulated) media change.
 */
int 
encrypted_ramdisk_media_changed(struct gendisk *gd)
{
	struct encrypted_ramdisk_dev *dev = gd->private_data;
	
	return dev->media_change;
}

/*
 * Revalidate.  WE DO NOT TAKE THE LOCK HERE, for fear of deadlocking
 * with open.  That needs to be reevaluated.
 */
int 
encrypted_ramdisk_revalidate(struct gendisk *gd)
{
	struct encrypted_ramdisk_dev *dev = gd->private_data;
	
	if (dev->media_change) {
		dev->media_change = 0;
		memset (dev->data, 0, dev->size);
	}
	return 0;
}

/*
 * The "invalidate" function runs out of the device timer; it sets
 * a flag to simulate the removal of the media.
 */
void 
encrypted_ramdisk_invalidate(unsigned long ldev)
{
	struct encrypted_ramdisk_dev *dev = (struct encrypted_ramdisk_dev *) ldev;

	spin_lock(&dev->lock);
	if (dev->users || !dev->data) 
		printk (KERN_WARNING "(ENCRYPTED_RAMDISK)  timer sanity check failed\n");
	else
		dev->media_change = 1;
	spin_unlock(&dev->lock);
}

/*
 * The ioctl() implementation
 */

int 
encrypted_ramdisk_ioctl (struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg)
{
	long size;
	struct hd_geometry geo;
	struct encrypted_ramdisk_dev *dev = filp->private_data;

	switch(cmd) {
	    case HDIO_GETGEO:
        	/*
		 * Get geometry: since we are a virtual device, we have to make
		 * up something plausible.  So we claim 16 sectors, four heads,
		 * and calculate the corresponding number of cylinders.  We set the
		 * start of data at sector four.
		 */
		size = dev->size*(hardsect_size/KERNEL_SECTOR_SIZE);
		geo.cylinders = (size & ~0x3f) >> 6;
		geo.heads = 4;
		geo.sectors = 16;
		geo.start = 4;
		if (copy_to_user((void __user *) arg, &geo, sizeof(geo)))
			return -EFAULT;
		return 0;
	}

	return -ENOTTY; /* unknown command */
}



/*
 * The device operations structure.
 */
static struct 
block_device_operations encrypted_ramdisk_ops = {
	.owner           = THIS_MODULE,
	.open 	         = encrypted_ramdisk_open,
	.release 	 = encrypted_ramdisk_release,
	.media_changed   = encrypted_ramdisk_media_changed,
	.revalidate_disk = encrypted_ramdisk_revalidate,
	.ioctl	         = encrypted_ramdisk_ioctl
};


/*
 * Set up our internal device.
 */
static void 
setup_device(struct encrypted_ramdisk_dev *dev, int which)
{
	/*
	 * Get some memory.
	 */
	memset (dev, 0, sizeof (struct encrypted_ramdisk_dev));
	dev->size = nsectors*hardsect_size;
	dev->data = vmalloc(dev->size);
	if (dev->data == NULL) {
		printk (KERN_NOTICE "(ENCRYPTED_RAMDISK) vmalloc failure.\n");
		return;
	}
	spin_lock_init(&dev->lock);
	
	/*
	 * The timer which "invalidates" the device.
	 */
	init_timer(&dev->timer);
	dev->timer.data = (unsigned long) dev;
	dev->timer.function = encrypted_ramdisk_invalidate;
	
	/*
	 * The I/O queue, depending on whether we are using our own
	 * make_request function or not.
	 */
	switch (request_mode) {
	    case RM_NOQUEUE:
		dev->queue = blk_alloc_queue(GFP_KERNEL);
		if (dev->queue == NULL)
			goto out_vfree;
		blk_queue_make_request(dev->queue, encrypted_ramdisk_make_request);
		break;

	    case RM_FULL:
		dev->queue = blk_init_queue(encrypted_ramdisk_full_request, &dev->lock);
		if (dev->queue == NULL)
			goto out_vfree;
		break;

	    default:
		printk(KERN_NOTICE "(ENCRYPTED_RAMDISK) Bad request mode %d, using simple\n", request_mode);
        	/* fall into.. */
	
	    case RM_SIMPLE:
		dev->queue = blk_init_queue(encrypted_ramdisk_request, &dev->lock);
		if (dev->queue == NULL)
			goto out_vfree;
		break;
	}
	blk_queue_hardsect_size(dev->queue, hardsect_size);
	dev->queue->queuedata = dev;
	/*
	 * And the gendisk structure.
	 */
	dev->gd = alloc_disk(ENCRYPTED_RAMDISK_MINORS);
	if (! dev->gd) {
		printk (KERN_NOTICE "(ENCRYPTED_RAMDISK) alloc_disk failure\n");
		goto out_vfree;
	}
	dev->gd->major = encrypted_ramdisk_major;
	dev->gd->first_minor = which*ENCRYPTED_RAMDISK_MINORS;
	dev->gd->fops = &encrypted_ramdisk_ops;
	dev->gd->queue = dev->queue;
	dev->gd->private_data = dev;
	snprintf (dev->gd->disk_name, 32, "encrypted_ramdisk%c", which + 'a');
	set_capacity(dev->gd, nsectors*(hardsect_size/KERNEL_SECTOR_SIZE));
	add_disk(dev->gd);
	return;

  out_vfree:
	if (dev->data)
		vfree(dev->data);
}



static int 
__init encrypted_ramdisk_init(void)
{
	int i;
	
	cipher = crypto_alloc_cipher("aes", 0, CRYPTO_ALG_ASYNC);
	crypto_cipher_setkey(cipher, key, 27);
	/*
	 * Get registered.
	 */
	encrypted_ramdisk_major = register_blkdev(encrypted_ramdisk_major, "encrypted_ramdisk");
	if (encrypted_ramdisk_major <= 0) {
		printk(KERN_WARNING "(ENCRYPTED_RAMDISK) encrypted_ramdisk: unable to get major number\n");
		return -EBUSY;
	}
	/*
	 * Allocate the device array, and initialize each one.
	 */
	Devices = kmalloc(ndevices*sizeof (struct encrypted_ramdisk_dev), GFP_KERNEL);
	if (Devices == NULL)
		goto out_unregister;
	for (i = 0; i < ndevices; i++) 
		setup_device(Devices + i, i);
    
	return 0;

  out_unregister:
	unregister_blkdev(encrypted_ramdisk_major, "sbd");
	return -ENOMEM;
}

static void 
encrypted_ramdisk_exit(void)
{
	int i;

	for (i = 0; i < ndevices; i++) {
		struct encrypted_ramdisk_dev *dev = Devices + i;

		del_timer_sync(&dev->timer);
		if (dev->gd) {
			del_gendisk(dev->gd);
			put_disk(dev->gd);
		}
		if (dev->queue) {
			if (request_mode == RM_NOQUEUE)
				blk_put_queue(dev->queue);
			else
				blk_cleanup_queue(dev->queue);
		}
		if (dev->data)
			vfree(dev->data);
	}
	unregister_blkdev(encrypted_ramdisk_major, "encrypted_ramdisk");
	kfree(Devices);
	crypto_free_cipher(cipher);
}
	
module_init(encrypted_ramdisk_init);
module_exit(encrypted_ramdisk_exit);
