/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __NO_TRACE_KERN_SKEL_H__
#define __NO_TRACE_KERN_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct no_trace_kern {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rb;
	} maps;
	struct {
		struct bpf_program *no_trace;
	} progs;
	struct {
		struct bpf_link *no_trace;
	} links;
};

static void
no_trace_kern__destroy(struct no_trace_kern *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
no_trace_kern__create_skeleton(struct no_trace_kern *obj);

static inline struct no_trace_kern *
no_trace_kern__open_opts(const struct bpf_object_open_opts *opts)
{
	struct no_trace_kern *obj;
	int err;

	obj = (struct no_trace_kern *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = no_trace_kern__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	no_trace_kern__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct no_trace_kern *
no_trace_kern__open(void)
{
	return no_trace_kern__open_opts(NULL);
}

static inline int
no_trace_kern__load(struct no_trace_kern *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct no_trace_kern *
no_trace_kern__open_and_load(void)
{
	struct no_trace_kern *obj;
	int err;

	obj = no_trace_kern__open();
	if (!obj)
		return NULL;
	err = no_trace_kern__load(obj);
	if (err) {
		no_trace_kern__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
no_trace_kern__attach(struct no_trace_kern *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
no_trace_kern__detach(struct no_trace_kern *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *no_trace_kern__elf_bytes(size_t *sz);

static inline int
no_trace_kern__create_skeleton(struct no_trace_kern *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		goto err;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "no_trace_kern";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "rb";
	s->maps[0].map = &obj->maps.rb;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "no_trace";
	s->progs[0].prog = &obj->progs.no_trace;
	s->progs[0].link = &obj->links.no_trace;

	s->data = (void *)no_trace_kern__elf_bytes(&s->data_sz);

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -ENOMEM;
}

static inline const void *no_trace_kern__elf_bytes(size_t *sz)
{
	*sz = 6872;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x58\x15\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x16\0\
\x01\0\x85\0\0\0\x0e\0\0\0\xbf\x07\0\0\0\0\0\0\xb7\x01\0\0\x09\0\0\0\x85\0\0\0\
\x6d\0\0\0\xbf\x08\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\
\x18\0\0\0\xb7\x03\0\0\0\0\0\0\x85\0\0\0\x83\0\0\0\xbf\x06\0\0\0\0\0\0\x15\x06\
\x0d\0\0\0\0\0\x77\x07\0\0\x20\0\0\0\x63\x76\0\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\
\x15\x08\x01\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x73\x16\x14\0\0\0\0\0\xbf\x61\0\0\0\
\0\0\0\x07\x01\0\0\x04\0\0\0\xb7\x02\0\0\x10\0\0\0\x85\0\0\0\x10\0\0\0\xbf\x61\
\0\0\0\0\0\0\xb7\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\x4d\x49\x54\x2f\
\x47\x50\x4c\0\0\0\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\x03\0\x11\0\x9f\x28\0\0\0\0\0\
\0\0\xd8\0\0\0\0\0\0\0\x01\0\x58\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\
\0\0\x68\0\0\0\0\0\0\0\x06\0\x77\0\x10\x20\x25\x9f\x68\0\0\0\0\0\0\0\x78\0\0\0\
\0\0\0\0\x03\0\x77\0\x9f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x68\
\0\0\0\0\0\0\0\x01\0\x57\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\0\0\0\0\0\0\0\xd8\
\0\0\0\0\0\0\0\x01\0\x56\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x11\x01\x25\x0e\
\x13\x05\x03\x0e\x10\x17\x1b\x0e\x11\x01\x12\x06\0\0\x02\x34\0\x03\x0e\x49\x13\
\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x01\x01\x49\x13\0\0\x04\x21\0\x49\x13\
\x37\x0b\0\0\x05\x24\0\x03\x0e\x3e\x0b\x0b\x0b\0\0\x06\x24\0\x03\x0e\x0b\x0b\
\x3e\x0b\0\0\x07\x13\x01\x0b\x0b\x3a\x0b\x3b\x0b\0\0\x08\x0d\0\x03\x0e\x49\x13\
\x3a\x0b\x3b\x0b\x38\x0b\0\0\x09\x0f\0\x49\x13\0\0\x0a\x21\0\x49\x13\x37\x06\0\
\0\x0b\x34\0\x03\x0e\x49\x13\x3a\x0b\x3b\x05\0\0\x0c\x15\0\x49\x13\x27\x19\0\0\
\x0d\x16\0\x49\x13\x03\x0e\x3a\x0b\x3b\x0b\0\0\x0e\x15\x01\x49\x13\x27\x19\0\0\
\x0f\x05\0\x49\x13\0\0\x10\x0f\0\0\0\x11\x15\x01\x27\x19\0\0\x12\x2e\x01\x11\
\x01\x12\x06\x40\x18\x97\x42\x19\x03\x0e\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\
\x19\0\0\x13\x05\0\x03\x0e\x3a\x0b\x3b\x0b\x49\x13\0\0\x14\x34\0\x02\x17\x03\
\x0e\x3a\x0b\x3b\x0b\x49\x13\0\0\x15\x13\x01\x03\x0e\x0b\x0b\x3a\x0b\x3b\x0b\0\
\0\0\xcb\x02\0\0\x04\0\0\0\0\0\x08\x01\0\0\0\0\x0c\0\x2c\0\0\0\0\0\0\0\x40\0\0\
\0\0\0\0\0\0\0\0\0\xd8\0\0\0\x02\x54\0\0\0\x3f\0\0\0\x01\x19\x09\x03\0\0\0\0\0\
\0\0\0\x03\x4b\0\0\0\x04\x52\0\0\0\x0d\0\x05\x5d\0\0\0\x06\x01\x06\x62\0\0\0\
\x08\x07\x02\x76\0\0\0\x6e\0\0\0\x02\x0c\x09\x03\0\0\0\0\0\0\0\0\x07\x10\x02\
\x09\x08\x79\0\0\0\x8b\0\0\0\x02\x0a\0\x08\x82\0\0\0\xa3\0\0\0\x02\x0b\x08\0\
\x09\x90\0\0\0\x03\x9c\0\0\0\x04\x52\0\0\0\x1b\0\x05\x7e\0\0\0\x05\x04\x09\xa8\
\0\0\0\x03\x9c\0\0\0\x0a\x52\0\0\0\0\0\x04\0\0\x0b\x8e\0\0\0\xc3\0\0\0\x04\x68\
\x01\x09\xc8\0\0\0\x0c\xcd\0\0\0\x0d\xd8\0\0\0\xbe\0\0\0\x03\x1f\x05\xa7\0\0\0\
\x07\x08\x0b\xc4\0\0\0\xeb\0\0\0\x04\x6a\x0a\x09\xf0\0\0\0\x0e\xfb\0\0\0\x0f\
\x02\x01\0\0\0\x05\xd4\0\0\0\x05\x08\x0d\x0d\x01\0\0\xea\0\0\0\x03\x1b\x05\xdd\
\0\0\0\x07\x04\x0b\xf0\0\0\0\x20\x01\0\0\x04\x2e\x0c\x09\x25\x01\0\0\x0e\x3a\
\x01\0\0\x0f\x3a\x01\0\0\x0f\xcd\0\0\0\x0f\xcd\0\0\0\0\x10\x0b\x04\x01\0\0\x47\
\x01\0\0\x04\x81\x01\x09\x4c\x01\0\0\x0e\xfb\0\0\0\x0f\x3a\x01\0\0\x0f\x02\x01\
\0\0\0\x0b\x19\x01\0\0\x68\x01\0\0\x04\x40\x0c\x09\x6d\x01\0\0\x11\x0f\x3a\x01\
\0\0\x0f\xcd\0\0\0\0\x12\0\0\0\0\0\0\0\0\xd8\0\0\0\x01\x5a\x2c\x01\0\0\x01\x04\
\x9c\0\0\0\x13\x35\x01\0\0\x01\x04\xda\x01\0\0\x14\0\0\0\0\xb9\x01\0\0\x01\x06\
\xfb\0\0\0\x14\x38\0\0\0\x6e\x01\0\0\x01\x08\x9c\0\0\0\x14\x75\0\0\0\xbd\x01\0\
\0\x01\x07\x7e\x02\0\0\x14\x98\0\0\0\xcd\x01\0\0\x01\x0c\x89\x02\0\0\0\x09\xdf\
\x01\0\0\x15\x9f\x01\0\0\x40\x05\x10\x08\x39\x01\0\0\x18\x02\0\0\x05\x11\0\x08\
\x7e\x01\0\0\xfb\0\0\0\x05\x12\x08\x08\x81\x01\0\0\x5f\x02\0\0\x05\x13\x10\x08\
\x98\x01\0\0\x72\x02\0\0\x05\x14\x40\0\x15\x72\x01\0\0\x08\x05\x09\x08\x79\0\0\
\0\x51\x02\0\0\x05\x0a\0\x08\x4c\x01\0\0\x58\x02\0\0\x05\x0b\x02\x08\x60\x01\0\
\0\x58\x02\0\0\x05\x0c\x03\x08\x6e\x01\0\0\x9c\0\0\0\x05\x0d\x04\0\x05\x3d\x01\
\0\0\x07\x02\x05\x52\x01\0\0\x08\x01\x03\x6b\x02\0\0\x04\x52\0\0\0\x06\0\x05\
\x86\x01\0\0\x07\x08\x03\x4b\0\0\0\x04\x52\0\0\0\0\0\x0d\x6b\x02\0\0\xc6\x01\0\
\0\x06\x2e\x09\x8e\x02\0\0\x15\xcd\x01\0\0\x18\x07\x08\x08\x6e\x01\0\0\x9c\0\0\
\0\x07\x09\0\x08\xd3\x01\0\0\xbb\x02\0\0\x07\x0a\x04\x08\xd8\x01\0\0\xc7\x02\0\
\0\x07\x0b\x14\0\x03\x4b\0\0\0\x04\x52\0\0\0\x10\0\x05\xe0\x01\0\0\x02\x01\0\
\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x32\x2e\x30\x2e\
\x31\x20\x28\x46\x65\x64\x6f\x72\x61\x20\x31\x32\x2e\x30\x2e\x31\x2d\x31\x2e\
\x66\x63\x33\x34\x29\0\x73\x72\x63\x2f\x6e\x6f\x5f\x74\x72\x61\x63\x65\x5f\x6b\
\x65\x72\x6e\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x76\x61\x67\x72\x61\x6e\x74\x2f\
\x6e\x79\x61\x6b\x6f\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x63\x68\x61\x72\0\x5f\
\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x72\
\x62\0\x74\x79\x70\x65\0\x69\x6e\x74\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\
\x73\0\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\
\x64\x5f\x74\x67\x69\x64\0\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\x20\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x36\x34\0\x62\x70\x66\x5f\
\x73\x65\x6e\x64\x5f\x73\x69\x67\x6e\x61\x6c\0\x6c\x6f\x6e\x67\x20\x69\x6e\x74\
\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x62\
\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\x72\x76\x65\0\x62\
\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\x6f\x6d\x6d\0\
\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x73\x75\x62\x6d\x69\x74\0\x6e\
\x6f\x5f\x74\x72\x61\x63\x65\0\x63\x74\x78\0\x65\x6e\x74\0\x75\x6e\x73\x69\x67\
\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x66\x6c\x61\x67\x73\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\x70\x72\x65\x65\x6d\x70\x74\x5f\x63\x6f\
\x75\x6e\x74\0\x70\x69\x64\0\x74\x72\x61\x63\x65\x5f\x65\x6e\x74\x72\x79\0\x69\
\x64\0\x61\x72\x67\x73\0\x6c\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x69\x6e\x74\0\x5f\x5f\x64\x61\x74\x61\0\x74\x72\x61\x63\x65\x5f\x65\x76\
\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x72\x65\
\x74\0\x70\x69\x64\x5f\x74\x67\x69\x64\0\x73\x69\x7a\x65\x5f\x74\0\x65\x76\x65\
\x6e\x74\0\x63\x6f\x6d\x6d\0\x73\x75\x63\x63\x65\x73\x73\0\x5f\x42\x6f\x6f\x6c\
\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x18\x02\0\0\x18\x02\0\0\x78\x02\0\0\0\0\0\0\
\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\
\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\
\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\
\0\0\x04\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\x1e\0\0\0\
\x05\0\0\0\x40\0\0\0\x2a\0\0\0\0\0\0\x0e\x07\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\
\x0a\0\0\0\x2d\0\0\0\x04\0\0\x04\x40\0\0\0\x47\0\0\0\x0b\0\0\0\0\0\0\0\x4b\0\0\
\0\x0e\0\0\0\x40\0\0\0\x4e\0\0\0\x10\0\0\0\x80\0\0\0\x53\0\0\0\x12\0\0\0\0\x02\
\0\0\x5a\0\0\0\x04\0\0\x04\x08\0\0\0\x19\0\0\0\x0c\0\0\0\0\0\0\0\x66\0\0\0\x0d\
\0\0\0\x10\0\0\0\x6c\0\0\0\x0d\0\0\0\x18\0\0\0\x7a\0\0\0\x02\0\0\0\x20\0\0\0\
\x7e\0\0\0\0\0\0\x01\x02\0\0\0\x10\0\0\0\x8d\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\
\0\x9b\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\x01\xa4\0\0\0\0\0\0\x01\x08\0\0\0\x40\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0f\0\0\0\x04\0\0\0\x06\0\0\0\xb6\0\0\0\0\0\0\
\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xbb\0\0\0\x09\0\0\0\xbf\0\0\0\x01\0\0\x0c\x13\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\x0d\0\0\0\x61\x02\0\0\0\0\
\0\x0e\x15\0\0\0\x01\0\0\0\x6a\x02\0\0\x01\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\x70\x02\0\0\x01\0\0\x0f\0\0\0\0\x16\0\0\0\0\0\0\0\x0d\0\0\0\0\x69\
\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x72\
\x62\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\
\x73\x5f\x65\x6e\x74\x65\x72\0\x65\x6e\x74\0\x69\x64\0\x61\x72\x67\x73\0\x5f\
\x5f\x64\x61\x74\x61\0\x74\x72\x61\x63\x65\x5f\x65\x6e\x74\x72\x79\0\x66\x6c\
\x61\x67\x73\0\x70\x72\x65\x65\x6d\x70\x74\x5f\x63\x6f\x75\x6e\x74\0\x70\x69\
\x64\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\0\x6c\x6f\x6e\x67\x20\x69\x6e\x74\0\
\x6c\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x63\x68\
\x61\x72\0\x63\x74\x78\0\x6e\x6f\x5f\x74\x72\x61\x63\x65\0\x74\x70\x2f\x73\x79\
\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x70\x74\
\x72\x61\x63\x65\0\x2f\x68\x6f\x6d\x65\x2f\x76\x61\x67\x72\x61\x6e\x74\x2f\x6e\
\x79\x61\x6b\x6f\x2f\x73\x72\x63\x2f\x6e\x6f\x5f\x74\x72\x61\x63\x65\x5f\x6b\
\x65\x72\x6e\x2e\x63\0\x20\x20\x73\x69\x7a\x65\x5f\x74\x20\x70\x69\x64\x5f\x74\
\x67\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\
\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x3b\0\x20\x20\x72\x65\x74\
\x20\x3d\x20\x62\x70\x66\x5f\x73\x65\x6e\x64\x5f\x73\x69\x67\x6e\x61\x6c\x28\
\x53\x49\x47\x4b\x49\x4c\x4c\x29\x3b\0\x20\x20\x65\x76\x65\x6e\x74\x20\x3d\x20\
\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\x72\x65\x73\x65\x72\x76\x65\
\x28\x26\x72\x62\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x2a\x65\x76\x65\x6e\x74\
\x29\x2c\x20\x30\x29\x3b\0\x20\x20\x69\x66\x20\x28\x65\x76\x65\x6e\x74\x29\0\
\x20\x20\x69\x6e\x74\x20\x70\x69\x64\x20\x3d\x20\x70\x69\x64\x5f\x74\x67\x69\
\x64\x20\x3e\x3e\x20\x33\x32\x3b\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\x2d\x3e\
\x70\x69\x64\x20\x3d\x20\x70\x69\x64\x3b\0\x20\x20\x20\x20\x65\x76\x65\x6e\x74\
\x2d\x3e\x73\x75\x63\x63\x65\x73\x73\x20\x3d\x20\x28\x72\x65\x74\x20\x3d\x3d\
\x20\x30\x29\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\
\x72\x65\x6e\x74\x5f\x63\x6f\x6d\x6d\x28\x26\x65\x76\x65\x6e\x74\x2d\x3e\x63\
\x6f\x6d\x6d\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x65\x76\x65\x6e\x74\x2d\x3e\
\x63\x6f\x6d\x6d\x29\x29\x3b\0\x20\x20\x20\x20\x62\x70\x66\x5f\x72\x69\x6e\x67\
\x62\x75\x66\x5f\x73\x75\x62\x6d\x69\x74\x28\x65\x76\x65\x6e\x74\x2c\x20\x30\
\x29\x3b\0\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x5f\x6c\x69\x63\x65\
\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\
\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\xcc\0\0\0\xe0\0\0\0\0\0\0\0\x08\0\0\0\
\xc8\0\0\0\x01\0\0\0\0\0\0\0\x14\0\0\0\x10\0\0\0\xc8\0\0\0\x0c\0\0\0\0\0\0\0\
\xe5\0\0\0\x0d\x01\0\0\x15\x1c\0\0\x10\0\0\0\xe5\0\0\0\x3d\x01\0\0\x09\x28\0\0\
\x28\0\0\0\xe5\0\0\0\x5f\x01\0\0\x0b\x34\0\0\x58\0\0\0\xe5\0\0\0\x96\x01\0\0\
\x07\x38\0\0\x60\0\0\0\xe5\0\0\0\xa3\x01\0\0\x16\x20\0\0\x68\0\0\0\xe5\0\0\0\
\xbf\x01\0\0\x10\x44\0\0\x78\0\0\0\xe5\0\0\0\xd5\x01\0\0\x1b\x40\0\0\x88\0\0\0\
\xe5\0\0\0\xd5\x01\0\0\x14\x40\0\0\x90\0\0\0\xe5\0\0\0\xf6\x01\0\0\x22\x48\0\0\
\xa0\0\0\0\xe5\0\0\0\xf6\x01\0\0\x05\x48\0\0\xb0\0\0\0\xe5\0\0\0\x33\x02\0\0\
\x05\x4c\0\0\xc8\0\0\0\xe5\0\0\0\x55\x02\0\0\x03\x58\0\0\0\0\0\0\x0c\0\0\0\xff\
\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\0\
\0\0\0\0\0\0\x15\x01\0\0\x04\0\xd3\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\
\x01\0\0\0\x01\0\0\x01\x73\x72\x63\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\
\x64\x65\x2f\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\x69\x63\0\x2f\x75\x73\x72\x2f\
\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\x2f\x75\x73\x72\x2f\x6c\x69\x62\
\x36\x34\x2f\x63\x6c\x61\x6e\x67\x2f\x31\x32\x2e\x30\x2e\x31\x2f\x69\x6e\x63\
\x6c\x75\x64\x65\0\0\x6e\x6f\x5f\x74\x72\x61\x63\x65\x5f\x6b\x65\x72\x6e\x2e\
\x63\0\x01\0\0\x6e\x6f\x5f\x74\x72\x61\x63\x65\x5f\x6b\x65\x72\x6e\x2e\x68\0\
\x01\0\0\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\0\x02\0\0\x62\x70\x66\x5f\x68\
\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x03\0\0\x6b\x65\x72\x6e\x5f\
\x63\x6f\x6d\x6d\x6f\x6e\x2e\x68\0\x01\0\0\x73\x74\x64\x64\x65\x66\x2e\x68\0\
\x04\0\0\x65\x76\x65\x6e\x74\x2e\x68\0\x01\0\0\0\0\x09\x02\0\0\0\0\0\0\0\0\x16\
\x05\x15\x0a\x14\x05\x09\x31\x05\x0b\x3f\x05\x07\x67\x05\x16\x03\x7a\x20\x05\
\x10\x03\x09\x20\x05\x1b\x2d\x05\x14\x06\x2e\x05\x22\x06\x22\x05\x05\x06\x2e\
\x06\x2f\x05\x03\x3f\x02\x02\0\x01\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xb0\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xe3\0\0\0\0\0\x03\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdc\0\0\0\0\0\x03\0\xc8\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x12\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x51\0\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x0d\0\0\0\
\0\0\0\0\x9c\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\xc0\0\0\0\x11\
\0\x05\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\x01\0\0\0\x0c\0\0\
\0\x06\0\0\0\0\0\0\0\x0a\0\0\0\x06\0\0\0\x0c\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\x12\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x16\0\0\0\0\0\0\0\x0a\0\0\0\x09\0\0\0\
\x1a\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x1e\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\
\x2b\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x37\0\0\0\0\0\0\0\x01\0\0\0\x0a\0\0\0\
\x4c\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x53\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\x5a\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x66\0\0\0\0\0\0\0\x01\0\0\0\x0c\0\0\0\
\x73\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x7f\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\x9d\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\xb8\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\xd2\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\xd9\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\xe0\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\xfc\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\x07\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x0e\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\
\0\x15\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x3c\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\
\0\0\x5d\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x7a\x01\0\0\0\0\0\0\x01\0\0\0\x04\
\0\0\0\x88\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x93\x01\0\0\0\0\0\0\x0a\0\0\0\
\x07\0\0\0\x9e\x01\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\xa2\x01\0\0\0\0\0\0\x0a\0\0\
\0\x07\0\0\0\xad\x01\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\xb1\x01\0\0\0\0\0\0\x0a\0\
\0\0\x07\0\0\0\xbc\x01\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\xc0\x01\0\0\0\0\0\0\x0a\
\0\0\0\x07\0\0\0\xcb\x01\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\xcf\x01\0\0\0\0\0\0\
\x0a\0\0\0\x07\0\0\0\xe0\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\xe8\x01\0\0\0\0\0\
\0\x0a\0\0\0\x07\0\0\0\xf4\x01\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\0\x02\0\0\0\0\0\
\0\x0a\0\0\0\x07\0\0\0\x0c\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x19\x02\0\0\0\0\
\0\0\x0a\0\0\0\x07\0\0\0\x21\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x2d\x02\0\0\0\
\0\0\0\x0a\0\0\0\x07\0\0\0\x39\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x45\x02\0\0\
\0\0\0\0\x0a\0\0\0\x07\0\0\0\x52\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x59\x02\0\
\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x6c\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x83\x02\
\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x8f\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x97\
\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\xa3\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\xaf\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\xc8\x02\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\
\0\x10\x02\0\0\0\0\0\0\0\0\0\0\x0c\0\0\0\x28\x02\0\0\0\0\0\0\0\0\0\0\x0a\0\0\0\
\x2c\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x50\0\
\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x70\0\0\0\0\
\0\0\0\0\0\0\0\x04\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x90\0\0\0\0\0\0\0\
\0\0\0\0\x04\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\
\0\x04\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xd0\0\0\0\0\0\0\0\0\0\0\0\x04\
\0\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xf0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\x14\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x18\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\
\xe0\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x0b\x0c\x0a\0\x2e\x64\x65\x62\x75\x67\
\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\
\x54\x46\x2e\x65\x78\x74\0\x2e\x6d\x61\x70\x73\0\x2e\x64\x65\x62\x75\x67\x5f\
\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\
\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\x63\x65\x6e\
\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\
\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x2e\x72\x65\x6c\
\x74\x70\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\
\x65\x72\x5f\x70\x74\x72\x61\x63\x65\0\x6e\x6f\x5f\x74\x72\x61\x63\x65\0\x2e\
\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\0\x6e\x6f\x5f\x74\x72\x61\x63\x65\x5f\x6b\
\x65\x72\x6e\x2e\x63\0\x72\x62\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\
\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x34\0\x4c\
\x42\x42\x30\x5f\x33\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xc3\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6b\x14\0\0\0\0\0\0\xea\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\
\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7b\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xc8\x0f\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x15\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x22\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\
\x01\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x52\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x01\0\0\0\0\0\
\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa5\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x35\x01\0\0\0\0\0\0\xbb\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\x01\0\0\0\0\0\0\xf7\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x37\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xe7\x02\0\0\0\0\0\0\xcf\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x33\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xd8\x0f\0\0\0\0\0\0\x70\x03\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x28\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb6\
\x05\0\0\0\0\0\0\xe6\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\xd7\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9c\x07\0\0\0\0\
\0\0\xa8\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd3\
\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x13\0\0\0\0\0\0\x20\0\0\0\
\0\0\0\0\x15\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\x0c\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x68\x13\0\0\0\0\0\0\xd0\0\0\0\0\0\0\0\x15\0\0\0\x0e\0\0\
\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x6e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x48\x0d\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x6a\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\
\x14\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x15\0\0\0\x10\0\0\0\x08\0\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\x5e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x0d\0\0\0\
\0\0\0\x19\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x5a\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x14\0\0\0\0\0\0\x10\0\
\0\0\0\0\0\0\x15\0\0\0\x12\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x43\0\0\0\
\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x68\x14\0\0\0\0\0\0\x03\0\0\
\0\0\0\0\0\x15\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcb\0\0\0\x02\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x0e\0\0\0\0\0\0\x38\x01\0\0\0\0\0\0\
\x01\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";
}

#endif /* __NO_TRACE_KERN_SKEL_H__ */
