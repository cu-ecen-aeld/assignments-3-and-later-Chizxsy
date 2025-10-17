/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Charlie Fischer"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    /**
     * TODO: handle open
     */
    // locate the start of aesd_dev struct based on cdev location in memory
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_count = 0;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    //private_data member can be used to get aesd_dev
    // buffer to fill using copy_to_user
    // counter the max number of writes to the buffer
    // read file position pointer to the read offset - ref circ buf wrapper
    // update point to the next offset

    // if return == count: requested number of bytes transfered
    // if 0< return < count: partial number of bytes returned
    // 0 end of file
    // negative error

    // lock before read
    // can be interrupted by sig
    if (mutex_lock_interruptible(&dev->lock)){
        retval = -ERESTARTSYS;
        goto out;
    }

    // nothing to read
    if (count == 0){
        retval = 0;
        goto out;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_count);
    if (entry == NULL){
        retval = 0;
        goto out;
    }
    // determine bytes to read from count and entry size
    size_t bytes_to_read = entry->size - entry_count;
    if (bytes_to_read > count){
        bytes_to_read = count;
    }
    
    // copy to user space
    if (copy_to_user(buf, entry->buffptr + entry_count, bytes_to_read)){
        retval = -EFAULT;
        goto out;
    }

    *f_pos += bytes_to_read;
    retval = bytes_to_read;

out:
    // unlock 
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;

    
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    if (mutex_lock_interruptible(&dev->lock)){
        retval = -ERESTARTSYS;
        goto out;
    }

    if (count == 0){
        retval = 0;
        goto out;
    }

    // kmalloc any length of write request
    if (dev->work_entry.size == 0){
        dev->work_entry.buffptr = kmalloc(count, GFP_KERNEL);
    } else {
        // if there is already data in the buffer entry
        dev->work_entry.buffptr = krealloc(dev->work_entry.buffptr, dev->work_entry.size + count, GFP_KERNEL);   
    }

    if (!dev->work_entry.buffptr){
        goto out;
    }

    // copy from user space
    if (copy_from_user((void *)(dev->work_entry.buffptr + dev->work_entry.size), buf, count)){
        retval = -EFAULT;
        goto out;
    }
    // increment working buffer size
    dev->work_entry.size += count;

    // search memory for a new line
    if ((memchr(dev->work_entry.buffptr, '\n', dev->work_entry.size)) != NULL){
        // add entry to buffer
        // memory leak
        aesd_circular_buffer_add_entry(&dev->buffer, &dev->work_entry);

        dev->work_entry.buffptr = NULL;
        dev->work_entry.size = 0;
    }
    retval = count;
    
out:
    mutex_unlock(&dev->lock);
    return retval;
}
// ----- IOCTL -----
loff_t aesd_llseek(struct file *filp, loff_t off, int whence){
    // scull device
    struct aesd_device *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    loff_t newpos;
    int index;
    size_t total_size = 0;


    if (mutex_lock_interruptible(&dev->lock)){
        return -ERESTARTSYS;
    }
    // get total entry size
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &dev->buffer, index){
        total_size += entry->size;
    }

    mutex_unlock(&dev->lock);
    
    switch(whence) {
        // SEEK SET
        case SEEK_SET:
            newpos = off;
            break;

        // SEEK CUR
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;

        // SEEK END
        case SEEK_END: 
            newpos = total_size + off;
            break;
        
        default:
            return -EINVAL;

    }
    // check if position is out of bounds
    if (newpos < 0 || newpos > total_size) {
        return -EINVAL;
    }

    filp->f_pos = newpos;
    return newpos;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
    struct aesd_device *dev = filp->private_data;
    struct aesd_seekto seekto;
    long retval = 0;
    uint8_t index;
    //loff_t newpos;
    size_t newpos = 0;

    // checks if the ioctl command is valid. From Google Gemini:
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC || _IOC_NR(cmd) > AESD_IOC_MAXNR) {
        return -ENOTTY;
    }

    switch(cmd){
        case AESDCHAR_IOCSEEKTO:
            if (copy_from_user(&seekto, (void __user *)arg, sizeof(seekto))){
                return -EFAULT;
            }
            
            if (mutex_lock_interruptible(&dev->lock)){
                return -ERESTARTSYS;
            }

            // check if the seek to command is with in the supported write operations
            if (seekto.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED){
                retval -EINVAL;
                goto out;
            }
            // check if seek is out of bounds
            buffer_index = (dev->buffer.out_offs + seekto.write_cmd) % AESDCHAR_MAX_WRITE_OPERATIONS;
            if (dev->buffer.entry[buffer_index].buffptr == NULL) {
                retval = -EINVAL;
                goto out;
            }

            if (seekto.write_cmd_offset >= dev->buffer.entry[buffer_index].size) {
                retval = -EINVAL;
                goto out;
            }
            // does the entry exist? 

            // calculate new position in file
            for (uint8_t i = 0; i < seekto.write_cmd; i++){
                // ring buffer output offset + command. Modulus handles wrapping. i.e. 10 mod 10 = 0. 11 mod 10 = 1
                index = (dev->buffer.out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
                newpos += dev->buffer.entry[index].size;
            }
            
            newpos += seekto.write_cmd_offset;

            // update new positon in file 
            filp->f_pos = newpos;

            break:

        default: 
            return -ENOTTY;
    }

out:
    mutex_unlock(&dev->lock);
    return retval;

}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */

    // init mutex
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);
    
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
        mutex_destroy(&aesd_device.lock);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

     // free kernel allocated memory for each buffer entry
     AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index){
        if (entry->buffptr){
            kfree(entry->buffptr);
        }
     }
     // free kernel allocated memory for partial buffer entries
     if (aesd_device.work_entry.buffptr){
        kfree(aesd_device.work_entry.buffptr);
     }

     // destroy mutex
     mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
