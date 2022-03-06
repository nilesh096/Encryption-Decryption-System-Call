#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <asm/current.h>
#include <linux/namei.h>
#include <linux/string.h>

#define SHA256_LEN 32

asmlinkage extern long (*sysptr)(void *arg);

typedef struct argument {
	char *outfile;
	char *infile;
	unsigned char flag;
	void *keybuf;
	int keylen;
} arguments;

/**
 * check_file_type - check the type of file 
 *
 * @stat:       struct kstat containing the stats of the file
 * @name:       name of the file
 *
 * This is the helper to check whether the file is a valid file or not
 * return -EINVAL if the file is a directory or not a regular file
 * return 0 if the file is a regular file
 */
int check_file_type(struct kstat *stat, const char *name)
{
	int ret = 0;

	if (!S_ISDIR(stat->mode)) {
		if (!S_ISREG(stat->mode)) {
			pr_alert("File %s is not a regular file\n", name);
			ret = -EINVAL;
		}
	} else {
		ret = -EINVAL;
		pr_alert("File %s is a directory\n", name);
	}
	return ret;
}


/**
 * verify_preamble - Compare the input file preamble with cipher key 
 *
 * @buf1:       buffer containing the cipher key 
 * @buf2:       buffer containing the input file preamble
 *
 * This is a function to check whether the preamble matches the
 * cipher key
 * 
 * Retrun true if the preamble matches the cipher key
 * Return false if there is a mismatch 
 * 
 */
bool verify_preamble(const void *buf1, const void *buf2)
{
	return memcmp(buf1, buf2, SHA256_LEN) == 0;
}

/**
 * read_preamble - Read the input file preamble which is 32 bytes 
 *
 * @buf:        buffer containing the cipher key
 * @input:      struct file which is a file descriptor of the 
 * 				input file
 *
 * This is a function to read the preamble from the input file 
 * and compare it with the cipher key (verify_preamble function)
 * 
 * Retrun 0 if the reading of the preamble is successful and 
 * 			matches with the cipher key
 * Return -ve value if reading fails or cipher key doesn't match the preamble
 * 
 */
int read_preamble(void *buf, struct file *input)
{
	int err = 0;
	void *rbuf = NULL;

	rbuf = kmalloc(SHA256_LEN, GFP_KERNEL);

	if (rbuf == NULL) {
		err = -ENOMEM;
		goto out_read;
	}

	err = kernel_read(input, rbuf, SHA256_LEN, &input->f_pos);
	if (err < 0)
		goto out_read;


	if (!verify_preamble(buf, rbuf)) {
		pr_alert("Preamble mismatch\n");
		err = -EACCES;
		goto out_read;
	}

out_read:
	if (rbuf) {
		pr_debug("Freeing read buffer for reading preamble");
		kfree(rbuf);
	}
	return err;
}

/**
 * write_preamble - write the cipher key to the temp file 
 *
 * @buf:        buffer containing the cipher key
 * @output:     struct file which is a file descriptor of the 
 * 				temporary file
 *
 * This is a function to write the preamble (cipher key) into the temporary file
 * 
 * Retrun 0 if successfully able to write the preamble
 * Return -ve value if error in writing preamble
 * 
 */

int write_preamble(void *buf, struct file *output)
{
	ssize_t wbytes = 0;
	
	wbytes = kernel_write(output, buf, SHA256_LEN, &output->f_pos);

	if (wbytes < 0) 
		return wbytes;

	return 0;
}

/**
 * file_stat - get the stats of the file
 *
 * @name:       Name of the file
 * @output:     struct kstat which will be populated with the 
 * 				stats of the file
 *
 * This is a function to get the stats of the file and populate the
 * struct kstat
 * 
 * Retrun 0 if vfs_stat is successful
 * Return -ve value if vfs_stat returns an error
 * 
 */
int file_stat(const char *name, struct kstat *fstat)
{
	int ret = 0;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	ret = vfs_stat((const char __user *)name, fstat);
	set_fs(old_fs);
	return ret;
}


/**
 * encdec - do encryption/decryption of the file based on the flag
 *
 * @iv:         iv data 
 * @req:     	struct skcipher_request holds all information needed
 *              to perform the cipher operation
 * @buf:        buffer containing the data to encrypt/decrypt
 * @buf_len:    length of bytes to  encrypt/decrypt
 * @sg:         struct sctterlist
 * @wait:       A helper struct for waiting for completion of async crypto operation
 * @flag:       conatins info to decrypt/encrypt
 * 
 *
 * This is a function to encrypt/decrypt the file with AES encryption 
 * in CTR mode (symmetric key cryptography)
 * 
 * Return the value from crypto_wait_req operation
 * 
 */
static int encdec(char *iv, struct skcipher_request *req, 
				void *buf, int buf_len, struct scatterlist *sg,
				struct crypto_wait *wait, unsigned int flag)
{
	int ret = 0;

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, wait);
	sg_init_one(sg, buf, buf_len);
	skcipher_request_set_crypt(req, sg, sg, buf_len, iv);
	crypto_init_wait(wait);

	if (flag & 0x01)
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), wait);
	else
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), wait);

	return ret;
}

/**
 * read_write - do read/write to/from a file;
 * 				encrypt the file if flag is 0x01
 * 				decrypt if flag is 0x02
 * 				just copy if flag is 0x04	
 *
 * @input:      struct file which the file descriptor of the input file
 * @req:     	struct file which the file descriptor of the output file
 * @key:        buffer containing the cipher key
 * @flag:    	flag to encrypt/decrypt/copy
 *
 * This is a function to read_write form/to a file 
 * and do encryption/decryption/copy based on flag value
 * 
 * Return 0 if read/write successful
 * Return -ve val if any operation fails
 */

int read_write(struct file *input, struct file *output, 
				void *key, unsigned int flag) 
{

	ssize_t read_bytes = 0, write_bytes = 0;
	int err = 0;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	void *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (buf == NULL) {
		err = -ENOMEM;
		goto out_rw;
	}
	
	if (!(!(flag & 0x01) && !(flag & 0x02))) {
		skcipher = crypto_alloc_skcipher("ctr-aes-aesni", 0, 0);
    	if (IS_ERR(skcipher)) {
        	pr_alert("ERROR: Failed to handle skcipher handle\n");
        	err =  PTR_ERR(skcipher);
			goto out_rw;
    	}

		req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    	if (req == NULL) {
        	pr_alert("Failed to allocate skcipher request\n");
        	err = -ENOMEM;
        	goto out_rw;
    	}

		ivdata = (char *)kmalloc(16, GFP_KERNEL);
    	if (!ivdata) {
        	pr_alert("Failed to allocate ivdata\n");
        	goto out_rw;
    	}
		memset(ivdata, 98765, 16);

		if (crypto_skcipher_setkey(skcipher, key, SHA256_LEN)) {
			pr_alert("Error in setting key in skcipher\n");
			err = -EAGAIN;
			goto out_rw;
		}
	}

	while ((read_bytes = kernel_read(input, buf, PAGE_SIZE, &input->f_pos)) > 0) {
		if (flag & 0x01 || flag & 0x02) {
			struct scatterlist *sg = NULL;
			struct crypto_wait *wait = NULL;

			sg = (struct scatterlist *)kmalloc(sizeof(struct scatterlist), GFP_KERNEL);
			if (!sg) {
				err = -ENOMEM;
				pr_alert("ERROR: Error in allocating memory for scatterlist\n");
				goto out_rw;
			}
			wait = (struct crypto_wait *)kmalloc(sizeof(struct crypto_wait), GFP_KERNEL);
			if (!wait) {
				err = -ENOMEM;
				pr_alert("ERROR: Error in allocating memory for crypto_wait\n");
				kfree(sg);
				goto out_rw;
			}

			err = encdec(ivdata, req, buf, read_bytes, sg, wait, flag);
			kfree(wait);
			wait = NULL;
			kfree(sg);
			sg = NULL;
		
			if (err < 0) {
				if (flag & 0x01) {
					pr_alert("ERROR: Encryption operation failed\n");
					goto out_rw;
				} else {
					pr_alert("ERROR: Decryption operation failed\n");
					goto out_rw;
				}
			}
		}

		write_bytes = kernel_write(output, buf, read_bytes, &output->f_pos);
		pr_info("Bytes written = %ld\n", write_bytes);

		if (write_bytes < 0) {
			pr_alert("Error in writing data to output file\n");
			err = write_bytes;
			goto out_rw;
		}
	}

out_rw:
	if (buf) {
		pr_debug("Cleanup: Cleaning buffer for read");
		kfree(buf);
	}

	if (skcipher) {
		pr_debug("Cleanup: Cleaning up skcipher");
		crypto_free_skcipher(skcipher);
	}

	if (req) {
		pr_debug("Cleanup: Cleaning up request");
        skcipher_request_free(req);
	}

	if (ivdata) {
		pr_debug("Cleanup: Cleaning up ivdata");
        kfree(ivdata);
	}
	return err;
}

/**
 * generate_hash - generate the cipher key
 *
 * @input:       input buffer containing the md5 hash of the password
 * @hash_length: lenght of the md5 hash
 * @output:      output buffer to which the cipher key would be written
 *
 * Generate the cipher key after hahsing the md5 hash with sha256 hash
 * 
 * Return 0 if hash created successfully
 * Return -ve val if hash creation fails
 */

int generate_hash(const u8 *input, unsigned int hash_length, u8 *output)
{
	int err = 0;
	struct shash_desc *desc = NULL;
	struct crypto_shash *alg = NULL;
	const char *hash_algo = "sha256";

	alg = crypto_alloc_shash(hash_algo, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(alg)) {
		pr_alert("crypto_alloc_shash failed\n");
		err = PTR_ERR(alg);
		goto out_hash;
	}

	desc = kmalloc(crypto_shash_descsize(alg) + sizeof(*desc), GFP_KERNEL);
	if (desc == NULL) {
		err = -ENOMEM;
		goto out_hash;
	}

	desc->tfm = alg;

	err = crypto_shash_digest(desc, input, hash_length, output);
	if (err < 0) {
		pr_alert("Failed to generate digest\n");
		goto out_hash;
	}
	
out_hash:
	if (desc != NULL) {
		pr_debug("Cleanup: Freeing struct shash_desc\n");
		desc->tfm = NULL;
		kfree(desc);
	}
	if ((alg != NULL) && (!IS_ERR(alg))) {
		pr_debug("Cleanup: Freeing hash algo struct\n");
		crypto_free_shash(alg);
	}
	return err;
}

void delete_file(struct file *fp, const char *name)
{
	inode_lock(fp->f_path.dentry->d_parent->d_inode);
	vfs_unlink(fp->f_path.dentry->d_parent->d_inode, fp->f_path.dentry, NULL);
	inode_unlock(fp->f_path.dentry->d_parent->d_inode);	
	pr_debug("File %s successfully deleted\n", name);
}

asmlinkage long cryptocopy(void *arg)
{
	bool file_exists = false;
	int ret = 0;
	void *hash_cipher_key = NULL;
	char *tmp_outfile = NULL;
	arguments *karg = NULL;
	struct filename *kinfname = NULL, *koutfname = NULL;
	struct file *kinfptr = NULL, *koutfptr = NULL, *koutfptr_tmp = NULL;
	struct kstat *infstat = NULL, *outfstat = NULL;

	if (arg == NULL) {
		ret = -EINVAL;
		goto out;
	}
	
	//allocate memory for getting arguments from user space to kernel space
	karg = (arguments *)kmalloc(sizeof(arguments), GFP_KERNEL);
	if (!karg) {
        ret = -ENOMEM;
        goto out;
    }
	karg->keybuf = NULL;

	//copy argument struct from user space to kernel space
	if (copy_from_user(karg, arg, sizeof(arguments))) {
		ret = -EFAULT;
		goto out;
	}
	
	if (karg->flag & 0x01 || karg->flag & 0x02) {

		if (!(((arguments *)arg)->keybuf))
			goto out;

		karg->keybuf = kmalloc(karg->keylen, GFP_KERNEL);

		if (!karg->keybuf) {
			ret = -ENOMEM;
			goto out;
		}

		//copy the md5 hash key from user to kernel space
		if (copy_from_user(karg->keybuf, ((arguments *)arg)->keybuf, karg->keylen)) {
			ret = -EFAULT;
			goto out;
		}

		hash_cipher_key = kmalloc(SHA256_LEN, GFP_KERNEL);
		if (hash_cipher_key == NULL) {
			ret = -ENOMEM;
			goto out;
		}
		memset(hash_cipher_key, 0, SHA256_LEN);

		ret = generate_hash((const u8 *)karg->keybuf, karg->keylen, (u8 *)hash_cipher_key);
		if (ret < 0)
			goto out;
	}

	//get name of input file
	kinfname = getname(karg->infile);

	if (IS_ERR(kinfname)) {
		ret = PTR_ERR(kinfname);
		pr_alert("Can't get the name of the input file\n");
		goto out;
	}
	pr_debug("Input Filename is %s\n", kinfname->name);

	//getname of output file
	koutfname = getname(karg->outfile);
	if (IS_ERR(koutfname)) {
		ret = PTR_ERR(koutfname);
		pr_alert("Can't get the name of the output file\n");
		goto out;
	}
	pr_debug("Output Filename is %s\n", koutfname->name);

	infstat = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);

	if (infstat == NULL) {
		ret = -ENOMEM;
		pr_alert("Unable to allocate memory for input file stat");
		goto out;
	}

	//get input file stat
	ret = file_stat(kinfname->name, infstat);
	if (ret < 0) {
		pr_alert("File %s doesn't exist\n", kinfname->name);
		goto out;
	}

	//check the file type of the input file
	ret = check_file_type(infstat, kinfname->name);
	if (ret < 0)
		goto out;

	outfstat = (struct kstat *)kmalloc(sizeof(struct kstat), GFP_KERNEL);

	if (outfstat == NULL) {
		ret = -ENOMEM;
		pr_alert("Unable to allocate memory for output file stat");
		goto out;
	}

	//get output file stat
	ret = file_stat(koutfname->name, outfstat);
	if (!ret) {
		file_exists = true;
		//check the file type of the output file
		ret = check_file_type(outfstat, koutfname->name);
		if (ret < 0)
			goto out;

		if (infstat->ino == outfstat->ino) {
			pr_alert("Input and Output file are the same\n");
			ret = -EINVAL;
			goto out;
		}
	}

	//open input file for reading
	kinfptr = filp_open(kinfname->name, O_RDONLY, 0);
	if (IS_ERR(kinfptr)) {
		ret = PTR_ERR(kinfptr);
		pr_alert("Input File %s can't be opened for reading\n", kinfname->name);
		goto out;
	}

	//open output file for writing, create if it doesn't exist
	koutfptr = filp_open(koutfname->name, O_WRONLY | O_CREAT, kinfptr->f_inode->i_mode);
	if (IS_ERR(koutfptr)) {
		ret = PTR_ERR(koutfptr);
		pr_alert("Output File %s can't be opened for writing", koutfname->name);
		goto out;
	}

	tmp_outfile = (char*)kmalloc(strlen(koutfname->name) + 14, GFP_KERNEL);
	sprintf(tmp_outfile, "%s_%d.tmp", koutfname->name, current->pid);

	//Open temp file for writing content to
	koutfptr_tmp = filp_open(tmp_outfile, O_CREAT|O_WRONLY, kinfptr->f_inode->i_mode);
	if (IS_ERR(koutfptr_tmp)) {
		ret = PTR_ERR(koutfptr_tmp);
		pr_alert("Unable to create temporary file\n");
		goto out_delete_file;
	}
	
	if (karg->flag & 0x01) {
		//write the preamble to the temp file
		ret = write_preamble(hash_cipher_key, koutfptr_tmp);
		if (ret < 0) {
			pr_alert("Failed to write preamble in the output file\n");
			goto out_delete_temp;
		}
	}
	if (karg->flag & 0x02) {
		//read the preamble from the input file
		ret = read_preamble(hash_cipher_key, kinfptr);
		if (ret < 0) {
			pr_alert("Failed to verfiy the preamble\n");
			goto out_delete_temp;
		}
	}

	//read/write with enc/dec/copy 
	ret = read_write(kinfptr, koutfptr_tmp, hash_cipher_key, karg->flag);

	if (ret < 0) {
		pr_alert("Error in enc/dec/copy\n");
		goto out_delete_temp;

	} else {
		pr_debug("Starting rename\n");
		lock_rename(koutfptr_tmp->f_path.dentry->d_parent, koutfptr->f_path.dentry->d_parent);
		ret = vfs_rename(koutfptr_tmp->f_path.dentry->d_parent->d_inode,
						koutfptr_tmp->f_path.dentry, koutfptr->f_path.dentry->d_parent->d_inode,
						koutfptr->f_path.dentry, NULL, 0);
		unlock_rename(koutfptr_tmp->f_path.dentry->d_parent, koutfptr->f_path.dentry->d_parent);

		if (ret < 0) {
			pr_alert("Rename failed\n");
			goto out_delete_temp;
		} else {
			pr_debug("Rename Successful\n");
			goto out;
		}
	}

out_delete_temp:
	delete_file(koutfptr_tmp, tmp_outfile);

out_delete_file:
	if (!file_exists)
		delete_file(koutfptr, koutfname->name);

out:
	if (kinfptr != NULL) {
		if (!IS_ERR(kinfptr)) {
			pr_debug("Cleanup: Closing input file");
    		filp_close(kinfptr, NULL);
		}
	}

	if (koutfptr != NULL) {
		if (!IS_ERR(koutfptr)) {
			pr_debug("Cleanup: Closing output file");
    		filp_close(koutfptr, NULL);
		}
	}

	if (koutfptr_tmp != NULL) {
		if (!IS_ERR(koutfptr_tmp)) {
			pr_debug("Cleanup: Closing temp file");
    		filp_close(koutfptr_tmp, NULL);
		}
	}

	if (koutfname != NULL) {
		if (!IS_ERR(koutfname)) {
			pr_debug("Cleanup: Freeing memory for struct output filename\n");
			putname(koutfname);
		}
	}

	if (kinfname != NULL) {
		if (!IS_ERR(kinfname)) {
			pr_debug("Cleanup: Freeing memory for struct input filename\n");
			putname(kinfname);
		}
	}

	if (karg) {
		if (karg->keybuf) {
			pr_debug("Cleanup: Freeing keybuf\n");
			kfree(karg->keybuf);
		}
		pr_debug("Cleanup: Freeing kernel structure to hold arguments\n");
		kfree(karg);
	}

	if (outfstat) {
		pr_debug("Cleanup: Freeing kstat for output file\n");
		kfree(outfstat);
	}

	if (infstat) {
		pr_debug("Cleanup: Freeing kstat for input file\n");
		kfree(infstat);
	}

	if (hash_cipher_key) {
		pr_debug("Cleanup: Freeing memory for hashed key which contains the hash of the hash key\n");
		kfree(hash_cipher_key);
	}

	if (tmp_outfile) {
		pr_debug("Cleanup: Freeing memory for temp outfile\n");
		kfree(tmp_outfile);
	}
	return ret;
}

static int __init init_sys_cryptocopy(void)
{
	printk("installed new sys_cryptocopy module\n");
	if (sysptr == NULL)
		sysptr = cryptocopy;
	return 0;
}
static void  __exit exit_sys_cryptocopy(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_cryptocopy module\n");
}
module_init(init_sys_cryptocopy);
module_exit(exit_sys_cryptocopy);
MODULE_LICENSE("GPL");
