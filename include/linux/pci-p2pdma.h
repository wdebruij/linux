/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCI Peer 2 Peer DMA support.
 *
 * Copyright (c) 2016-2018, Logan Gunthorpe
 * Copyright (c) 2016-2017, Microsemi Corporation
 * Copyright (c) 2017, Christoph Hellwig
 * Copyright (c) 2018, Eideticom Inc.
 */

#ifndef _LINUX_PCI_P2PDMA_H
#define _LINUX_PCI_P2PDMA_H

#include <linux/pci.h>
#include <linux/uio.h>

struct pci_p2pdma_pagemap {
	struct dev_pagemap pgmap;
	struct pci_dev *provider;
	u64 bus_offset;
};


struct p2pdma_pages_vec {
	struct iov_iter pages_iter;
	struct bio_vec *bv;
	size_t num_pages;
	size_t size;

	struct pci_p2pdma_pagemap p2p_pgmap;
	void *private_ptr;
};

struct block_device;
struct scatterlist;

#ifdef CONFIG_PCI_P2PDMA
int __pci_p2pdma_add_resource(struct pci_dev *pdev, int bar, size_t size,
		u64 offset, int hack_align_off);
static inline int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar, size_t size,
		u64 offset) {
	return __pci_p2pdma_add_resource(pdev, bar, size, offset, 0);
}
int pci_p2pdma_distance_many(struct pci_dev *provider, struct device **clients,
			     int num_clients, bool verbose);
bool pci_has_p2pmem(struct pci_dev *pdev);
struct pci_dev *pci_p2pmem_find_many(struct device **clients, int num_clients);
void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size);
void pci_free_p2pmem(struct pci_dev *pdev, void *addr, size_t size);
void pci_free_p2pmem_page(struct page* pg);
pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev, void *addr);
struct scatterlist *pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
					 unsigned int *nents, u32 length);
void pci_p2pmem_free_sgl(struct pci_dev *pdev, struct scatterlist *sgl);
void pci_p2pmem_publish(struct pci_dev *pdev, bool publish);
int pci_p2pdma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir, unsigned long attrs);
void pci_p2pdma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
		int nents, enum dma_data_direction dir, unsigned long attrs);
int pci_p2pdma_enable_store(const char *page, struct pci_dev **p2p_dev,
			    bool *use_p2pdma);
ssize_t pci_p2pdma_enable_show(char *page, struct pci_dev *p2p_dev,
			       bool use_p2pdma);
void pci_p2pdma_compute_maptype_if_not_cached(struct dev_pagemap *pgmap,
					      struct pci_dev *client);
#else /* CONFIG_PCI_P2PDMA */
static inline int pci_p2pdma_add_resource(struct pci_dev *pdev, int bar,
		size_t size, u64 offset)
{
	return -EOPNOTSUPP;
}
static inline int pci_p2pdma_distance_many(struct pci_dev *provider,
	struct device **clients, int num_clients, bool verbose)
{
	return -1;
}
static inline bool pci_has_p2pmem(struct pci_dev *pdev)
{
	return false;
}
static inline struct pci_dev *pci_p2pmem_find_many(struct device **clients,
						   int num_clients)
{
	return NULL;
}
static inline void *pci_alloc_p2pmem(struct pci_dev *pdev, size_t size)
{
	return NULL;
}
static inline void pci_free_p2pmem(struct pci_dev *pdev, void *addr,
		size_t size)
{
}
static inline void pci_free_p2pmem_page(struct page* pg)
{
}
static inline pci_bus_addr_t pci_p2pmem_virt_to_bus(struct pci_dev *pdev,
						    void *addr)
{
	return 0;
}
static inline struct scatterlist *pci_p2pmem_alloc_sgl(struct pci_dev *pdev,
		unsigned int *nents, u32 length)
{
	return NULL;
}
static inline void pci_p2pmem_free_sgl(struct pci_dev *pdev,
		struct scatterlist *sgl)
{
}
static inline void pci_p2pmem_publish(struct pci_dev *pdev, bool publish)
{
}
static inline int pci_p2pdma_map_sg_attrs(struct device *dev,
		struct scatterlist *sg, int nents, enum dma_data_direction dir,
		unsigned long attrs)
{
	return 0;
}
static inline void pci_p2pdma_unmap_sg_attrs(struct device *dev,
		struct scatterlist *sg, int nents, enum dma_data_direction dir,
		unsigned long attrs)
{
}
static inline int pci_p2pdma_enable_store(const char *page,
		struct pci_dev **p2p_dev, bool *use_p2pdma)
{
	*use_p2pdma = false;
	return 0;
}
static inline ssize_t pci_p2pdma_enable_show(char *page,
		struct pci_dev *p2p_dev, bool use_p2pdma)
{
	return sprintf(page, "none\n");
}
void pci_p2pdma_compute_maptype_if_not_cached(struct dev_pagemap *pgmap,
					      struct pci_dev *client)
{
}
#endif /* CONFIG_PCI_P2PDMA */


static inline int pci_p2pdma_distance(struct pci_dev *provider,
	struct device *client, bool verbose)
{
	return pci_p2pdma_distance_many(provider, &client, 1, verbose);
}

static inline struct pci_dev *pci_p2pmem_find(struct device *client)
{
	return pci_p2pmem_find_many(&client, 1);
}

static inline int pci_p2pdma_map_sg(struct device *dev, struct scatterlist *sg,
				    int nents, enum dma_data_direction dir)
{
	return pci_p2pdma_map_sg_attrs(dev, sg, nents, dir, 0);
}

static inline void pci_p2pdma_unmap_sg(struct device *dev,
		struct scatterlist *sg, int nents, enum dma_data_direction dir)
{
	pci_p2pdma_unmap_sg_attrs(dev, sg, nents, dir, 0);
}

#endif /* _LINUX_PCI_P2P_H */
