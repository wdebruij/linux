// SPDX-License-Identifier: GPL-2.0
/* XSKMAP used for AF_XDP sockets
 * Copyright(c) 2018 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/bpf.h>
#include <linux/capability.h>
#include <net/xdp_sock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <net/sock.h>

struct xsk_map_entry {
	struct xdp_sock *xs;
	struct rcu_head rcu;
};

struct xsk_map {
	struct bpf_map map;
	struct xsk_map_entry **xsk_map;
	unsigned long __percpu *flush_needed;
};

static u64 xsk_map_bitmap_size(const union bpf_attr *attr)
{
	return BITS_TO_LONGS((u64) attr->max_entries) * sizeof(unsigned long);
}

static struct bpf_map *xsk_map_alloc(union bpf_attr *attr)
{
	struct xsk_map *m;
	int err = -EINVAL;
	u64 cost;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);

	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    attr->value_size != 4 ||
	    attr->map_flags & ~(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY))
		return ERR_PTR(-EINVAL);

	m = kzalloc(sizeof(*m), GFP_USER);
	if (!m)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&m->map, attr);

	cost = (u64)m->map.max_entries * sizeof(struct xsk_map_entry *);
	cost += xsk_map_bitmap_size(attr) * num_possible_cpus();
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_m;

	m->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	/* Notice returns -EPERM on if map size is larger than memlock limit */
	err = bpf_map_precharge_memlock(m->map.pages);
	if (err)
		goto free_m;

	m->flush_needed = __alloc_percpu(xsk_map_bitmap_size(attr),
					    __alignof__(unsigned long));
	if (!m->flush_needed)
		goto free_m;

	m->xsk_map = bpf_map_area_alloc(m->map.max_entries *
					   sizeof(struct xsk_map_entry *),
					   m->map.numa_node);
	if (!m->xsk_map)
		goto free_percpu;
	return &m->map;

free_percpu:
	free_percpu(m->flush_needed);
free_m:
	kfree(m);
	return ERR_PTR(err);
}

static void xsk_map_free(struct bpf_map *map)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	int i, cpu;

	/* At this point bpf_prog->aux->refcnt == 0 and this
	 * map->refcnt == 0, so the programs (can be more than one
	 * that used this map) were disconnected from events. Wait for
	 * outstanding critical sections in these programs to
	 * complete. The rcu critical section only guarantees no
	 * further reads against xsk_map. It does __not__ ensure
	 * pending flush operations (if any) are complete.
	 */

	synchronize_rcu();

	/* To ensure all pending flush operations have completed wait
	 * for flush bitmap to indicate all flush_needed bits to be
	 * zero on _all_ cpus.  Because the above synchronize_rcu()
	 * ensures the map is disconnected from the program we can
	 * assume no new bits will be set.
	 */
	for_each_online_cpu(cpu) {
		unsigned long *bitmap = per_cpu_ptr(m->flush_needed, cpu);

		while (!bitmap_empty(bitmap, map->max_entries))
			cond_resched();
	}

	for (i = 0; i < map->max_entries; i++) {
		struct xsk_map_entry *entry;

		entry = m->xsk_map[i];
		if (!entry)
			continue;

		sock_put((struct sock *)entry->xs);
		kfree(entry);
	}

	free_percpu(m->flush_needed);
	bpf_map_area_free(m->xsk_map);
	kfree(m);
}

static int xsk_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = next_key;

	if (index >= m->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == m->map.max_entries - 1)
		return -ENOENT;
	*next = index + 1;
	return 0;
}

struct xdp_sock *__xsk_map_lookup_elem(struct bpf_map *map, u32 key)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	struct xsk_map_entry *entry;

	if (key >= map->max_entries)
		return NULL;

	entry = READ_ONCE(m->xsk_map[key]);
	return entry ? entry->xs : NULL;
}

int __xsk_map_redirect(struct bpf_map *map, u32 index,
		       struct xdp_buff *xdp, struct xdp_sock *xs)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	unsigned long *bitmap = this_cpu_ptr(m->flush_needed);
	int err;

	err = xsk_rcv(xs, xdp);
	if (err)
		return err;

	__set_bit(index, bitmap);
	return 0;
}

void __xsk_map_flush(struct bpf_map *map)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	unsigned long *bitmap = this_cpu_ptr(m->flush_needed);
	u32 bit;

	for_each_set_bit(bit, bitmap, map->max_entries) {
		struct xsk_map_entry *entry = READ_ONCE(m->xsk_map[bit]);

		/* This is possible if the entry is removed by user
		 * space between xdp redirect and flush op.
		 */
		if (unlikely(!entry))
			continue;

		__clear_bit(bit, bitmap);
		xsk_flush(entry->xs);
	}
}

static void *xsk_map_lookup_elem(struct bpf_map *map, void *key)
{
	return NULL;
}

static void __xsk_map_entry_free(struct rcu_head *rcu)
{
	struct xsk_map_entry *entry;

	entry = container_of(rcu, struct xsk_map_entry, rcu);
	xsk_flush(entry->xs);
	sock_put((struct sock *)entry->xs);
	kfree(entry);
}

static int xsk_map_update_elem(struct bpf_map *map, void *key, void *value,
			       u64 map_flags)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	struct xsk_map_entry *entry, *old_entry;
	u32 i = *(u32 *)key, fd = *(u32 *)value;
	struct socket *sock;
	int err;

	if (unlikely(map_flags > BPF_EXIST))
		return -EINVAL;
	if (unlikely(i >= m->map.max_entries))
		return -E2BIG;
	if (unlikely(map_flags == BPF_NOEXIST))
		return -EEXIST;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err;

	if (sock->sk->sk_family != PF_XDP) {
		sockfd_put(sock);
		return -EOPNOTSUPP;
	}

	if (!xsk_is_setup_for_bpf_map((struct xdp_sock *)sock->sk)) {
		sockfd_put(sock);
		return -EOPNOTSUPP;
	}

	entry = kmalloc_node(sizeof(*entry), GFP_ATOMIC | __GFP_NOWARN,
			     map->numa_node);
	if (!entry) {
		sockfd_put(sock);
		return -ENOMEM;
	}

	sock_hold(sock->sk);
	entry->xs = (struct xdp_sock *)sock->sk;

	old_entry = xchg(&m->xsk_map[i], entry);
	if (old_entry)
		call_rcu(&old_entry->rcu, __xsk_map_entry_free);

	sockfd_put(sock);
	return 0;
}

static int xsk_map_delete_elem(struct bpf_map *map, void *key)
{
	struct xsk_map *m = container_of(map, struct xsk_map, map);
	struct xsk_map_entry *old_entry;
	int k = *(u32 *)key;

	if (k >= map->max_entries)
		return -EINVAL;

	old_entry = xchg(&m->xsk_map[k], NULL);
	if (old_entry)
		call_rcu(&old_entry->rcu, __xsk_map_entry_free);

	return 0;
}

const struct bpf_map_ops xsk_map_ops = {
	.map_alloc = xsk_map_alloc,
	.map_free = xsk_map_free,
	.map_get_next_key = xsk_map_get_next_key,
	.map_lookup_elem = xsk_map_lookup_elem,
	.map_update_elem = xsk_map_update_elem,
	.map_delete_elem = xsk_map_delete_elem,
};


