/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcpy */
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>
#include "data_reg.h"
#include "expr_ops.h"

#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif

struct nft_expr_lookup {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	char			set_name[IFNAMSIZ];
};

static int
nft_rule_expr_lookup_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, size_t data_len)
{
	struct nft_expr_lookup *lookup = (struct nft_expr_lookup *)e->data;

	switch(type) {
	case NFT_EXPR_LOOKUP_SREG:
		lookup->sreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_LOOKUP_DREG:
		lookup->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_LOOKUP_SET:
		memcpy(lookup->set_name, data, IFNAMSIZ);
		lookup->set_name[IFNAMSIZ-1] = '\0';
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_lookup_get(struct nft_rule_expr *e, uint16_t type, size_t *data_len)
{
	struct nft_expr_lookup *lookup = (struct nft_expr_lookup *)e->data;

	switch(type) {
	case NFT_EXPR_LOOKUP_SREG:
		if (e->flags & (1 << NFT_EXPR_LOOKUP_SREG)) {
			*data_len = sizeof(lookup->sreg);
			return &lookup->sreg;
		}
		break;
	case NFT_EXPR_LOOKUP_DREG:
		if (e->flags & (1 << NFT_EXPR_LOOKUP_DREG)) {
			*data_len = sizeof(lookup->dreg);
			return &lookup->dreg;
		}
		break;
	case NFT_EXPR_LOOKUP_SET:
		if (e->flags & (1 << NFT_EXPR_LOOKUP_SET))
			return lookup->set_name;
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_lookup_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_LOOKUP_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_LOOKUP_SREG:
	case NFTA_LOOKUP_DREG:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_LOOKUP_SET:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_lookup_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_lookup *lookup = (struct nft_expr_lookup *)e->data;

	if (e->flags & (1 << NFT_EXPR_LOOKUP_SREG))
		mnl_attr_put_u32(nlh, NFTA_LOOKUP_SREG, htonl(lookup->sreg));
	if (e->flags & (1 << NFT_EXPR_LOOKUP_DREG))
		mnl_attr_put_u32(nlh, NFTA_LOOKUP_DREG, htonl(lookup->dreg));
	if (e->flags & (1 << NFT_EXPR_LOOKUP_SET))
		mnl_attr_put_strz(nlh, NFTA_LOOKUP_SET, lookup->set_name);
}

static int
nft_rule_expr_lookup_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_lookup *lookup = (struct nft_expr_lookup *)e->data;
	struct nlattr *tb[NFTA_LOOKUP_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_rule_expr_lookup_cb, tb) < 0)
		return -1;

	if (tb[NFTA_LOOKUP_SREG]) {
		lookup->sreg = ntohl(mnl_attr_get_u32(tb[NFTA_LOOKUP_SREG]));
		e->flags |= (1 << NFT_EXPR_LOOKUP_SREG);
	}
	if (tb[NFTA_LOOKUP_DREG]) {
		lookup->dreg = ntohl(mnl_attr_get_u32(tb[NFTA_LOOKUP_DREG]));
		e->flags |= (1 << NFT_EXPR_LOOKUP_DREG);
	}
	if (tb[NFTA_LOOKUP_SET]) {
		strcpy(lookup->set_name, mnl_attr_get_str(tb[NFTA_LOOKUP_SET]));
		e->flags |= (1 << NFT_EXPR_LOOKUP_SET);
	}

	return ret;
}

static int
nft_rule_expr_lookup_snprintf_xml(char *buf, size_t size,
				  struct nft_expr_lookup *l)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "<set>%s</set><sreg>%u</sreg><dreg>%u</dreg>",
			l->set_name, l->sreg, l->dreg);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_lookup_snprintf_default(char *buf, size_t size,
				      struct nft_expr_lookup *l)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "set=%s sreg=%u dreg=%u",
			l->set_name, l->sreg, l->dreg);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_lookup_snprintf(char *buf, size_t size, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_lookup *lookup = (struct nft_expr_lookup *)e->data;

	switch(type) {
	case NFT_RULE_O_XML:
		return nft_rule_expr_lookup_snprintf_xml(buf, size, lookup);
	case NFT_RULE_O_DEFAULT:
		return nft_rule_expr_lookup_snprintf_default(buf, size, lookup);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_lookup = {
	.name		= "lookup",
	.alloc_len	= sizeof(struct nft_expr_lookup),
	.max_attr	= NFTA_LOOKUP_MAX,
	.set		= nft_rule_expr_lookup_set,
	.get		= nft_rule_expr_lookup_get,
	.parse		= nft_rule_expr_lookup_parse,
	.build		= nft_rule_expr_lookup_build,
	.snprintf	= nft_rule_expr_lookup_snprintf,
};