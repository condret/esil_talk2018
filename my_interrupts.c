#include <r_util.h>
#include <r_anal.h>
#include <r_io.h>
#include <stdio.h>

typedef struct interrupt_user_t {
	RIODesc *in;
	RIODesc *out;
	RIODesc *err;
	SdbMini *seek_tracker;
} InterruptUser;

static RIODesc *__open (RIO *io, const char *path, int rw, int mode) {
	RIODesc *desc;
	int *fd;

	desc = R_NEW0 (RIODesc);
	if (!desc) {
		return NULL;
	}
	fd = desc->data = R_NEW(int);
	if (!desc->data) {
		free(desc);
		return NULL;
	}

	if (!strcmp (path, "stdin")) {
		desc->fd = fd[0] = 0;
		desc->flags = 4;
	} else if (!strcmp (path, "stdout")) {
		desc->fd = fd[0] = 1;
		desc->flags = 6;
	} else {
		desc->fd = fd[0] = 2;
		desc->flags = 6;
	}

	return desc;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	int *fd = (int *)desc->data;
	
	return (int)read (fd[0], buf, len);
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int len) {
	int *fd = (int *)desc->data;

	return (int)write (fd[0], buf, len);
}

static bool __check(RIO *io, const char *path, bool many) {
	return (!strcmp (path, "stdin")) || (!strcmp (path, "stdout")) || (!strcmp (path, "stderr"));
}

static int __close (RIODesc *desc) {
	if (!desc) {
		return -1;
	}
	free (desc->data);
	return 0;
}

static ut64 __lseek (RIO *io, RIODesc *desc, ut64 off, int whence) {
	return (whence == R_IO_SEEK_END) ? 0xffffffffffffff : 
		(whence == R_IO_SEEK_SET) ? off : 0LL;
}

static bool __is_chardev (RIODesc *desc) {
	return true;
}

RIOPlugin r_io_wild_stdio_plugin = {
	.name = "stdio",
	.desc = "allows accessing stdio from RIO",
	.license = "LGPL3",
	.is_chardevice = __is_chardev,
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.write = __write,
	.lseek = __lseek,
};

static ut32 read_wrap(RAnalEsil *esil, SdbMini *seek_tracker) {
	RAnal *anal = esil->anal;
	RIO *io = anal->iob.io;
	int fd = r_reg_getv (anal->reg, "ebx");
	ut32 off_dst = r_reg_getv (anal->reg, "ecx");
	ut32 blen = r_reg_getv (anal->reg, "edx");
	ut8 *buf = R_NEWS (ut8, blen);
	ut64 off_src = 0LL;
	if (fd > 2) {
		off_src = dict_get (seek_tracker, fd);
	}

	blen = r_io_fd_read_at (io, fd, off_src, buf, blen);
	r_io_write_at (io, off_dst, buf, blen);

	if (fd > 2) {
		dict_set (seek_tracker, fd, off_src + blen, NULL);
	}
	free (buf);
}

static ut32 write_wrap(RAnalEsil *esil, SdbMini *seek_tracker) {
	RAnal *anal = esil->anal;
	RIO *io = anal->iob.io;
	int fd = r_reg_getv (anal->reg, "ebx");
	ut32 off_src = r_reg_getv (anal->reg, "ecx");
	ut32 blen = r_reg_getv (anal->reg, "edx");
	ut8 *buf = R_NEWS (ut8, blen);
	ut64 off_dst = 0LL;
	if (fd > 2) {
		off_dst = dict_get (seek_tracker, fd);
	}

	r_io_read_at (io, off_src, buf, blen);
	blen = r_io_fd_write_at (io, fd, off_dst, buf, blen);

	if (fd > 2) {
		dict_set (seek_tracker, fd, off_dst + blen, NULL);
	}
	free (buf);
	return blen;
}

static ut32 open_wrap (RAnalEsil *esil, SdbMini *seek_tracker) {
	ut64 off;
	int flags;
	int mode;
	int fd;
	char buf[2048];
	RAnal *anal = esil->anal;
	RIO *io = anal->iob.io;

	off = r_reg_getv(anal->reg, "ebx");
	flags = r_reg_getv(anal->reg, "ecx");
	mode = r_reg_getv(anal->reg, "edx");

	r_io_read_at (io, off, buf, 2048);

	fd = r_io_fd_open (io, buf, flags, mode);
	dict_set (seek_tracker, fd, 0LL, NULL);
	return fd;
}

static ut32 lseek_wrap (RAnalEsil *esil, SdbMini *seek_tracker) {
	RAnal *anal = esil->anal;
	RIO *io = anal->iob.io;
	ut64 off, ret;
	int fd = r_reg_getv(anal->reg, "ebx");
	int whence;

	if (fd < 3) {
		return 0;
	}

	off = r_reg_getv (anal->reg, "ecx");
	whence = r_reg_getv (anal->reg, "edx");

	switch (whence) {
	case 0:		//SEEK_SET
		dict_set (seek_tracker, fd, off, NULL);
		ret = off;
		break;
	case 1:		//SEEK_CUR
		ret = (dict_get (seek_tracker, fd) + off) & 0xffffffff;	
		break;
	default:	//SEEK_END
		ret = (r_io_fd_size (io, fd) + off) & 0xffffffff;
		dict_set (seek_tracker, fd, (r_io_fd_size(io, fd) + off)  & 0xffffffff, NULL);
		break;
	}
	dict_set (seek_tracker, fd, ret, NULL);
	return ret;	
}

static bool my_intx80_fcn (RAnalEsil *esil, ut32 interrupt, void *user) {
	InterruptUser *iu = (InterruptUser *)user;
	SdbMini *seek_tracker = iu->seek_tracker;
	ut32 syscall;

	if (!seek_tracker) {
		eprintf ("user is NULL, damn\n");
		return false;
	}

	syscall = r_reg_getv (esil->anal->reg, "eax");
	switch (syscall) {
	case 3:		//read
		r_reg_setv (esil->anal->reg, "eax", write_wrap (esil, seek_tracker));
		break;
	case 4:		//write
		r_reg_setv (esil->anal->reg, "eax", write_wrap (esil, seek_tracker));
		break;
	case 5:		//open
		r_reg_setv (esil->anal->reg, "eax", open_wrap (esil, seek_tracker));
		break;
	case 19:	//lseek
		r_reg_setv (esil->anal->reg, "eax", lseek_wrap (esil, seek_tracker));
		break;
	default:
		eprintf ("syscall: %d\n", syscall);
	}
	return true;
}

static void *my_init (RAnalEsil *esil) {
	InterruptUser *iu = R_NEW (InterruptUser);
	iu->out = r_io_desc_open_plugin (esil->anal->iob.io, &r_io_wild_stdio_plugin, "stdout", 6, 0644);
	iu->in = r_io_desc_open_plugin (esil->anal->iob.io, &r_io_wild_stdio_plugin, "stdin", 6, 0644);
	iu->err = r_io_desc_open_plugin (esil->anal->iob.io, &r_io_wild_stdio_plugin, "stderr", 6, 0644);
	iu->seek_tracker = dict_new(sizeof(ut32), NULL);
	return iu;
}

static void my_fini (void *user) {
	InterruptUser *iu = (InterruptUser *)user;
#if 0
	r_io_desc_close (iu->in);
	r_io_desc_close (iu->out);
	r_io_desc_close (iu->err);
#endif
	dict_free(iu->seek_tracker);
	free (iu);
}

RAnalEsilInterruptHandler my_handler = {
	.num = 0x80,
	.init = my_init,
	.cb = my_intx80_fcn,
	.fini = my_fini,
};

static bool my_intx03_fcn (RAnalEsil *esil, ut32 interrupt, void *user) {
	esil->parse_stop = 1;

	return true;
}

RAnalEsilInterruptHandler break_handler = {
	.num = 0x03,
	.init = NULL,
	.cb = my_intx03_fcn,
	.fini = NULL,
};

RAnalEsilInterruptHandler *interrupts[] = {
	&break_handler,
	&my_handler,
	NULL,
};
