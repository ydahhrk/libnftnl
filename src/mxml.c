/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2013 by Arturo Borrero Gonzalez <arturo.borrero.glez@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */
#include "internal.h"
#include "expr_ops.h"
#include <stdint.h>
#include <limits.h>

#include <linux/netfilter/nf_tables.h>
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>
#include <libnftables/set.h>

#ifdef XML_PARSING
mxml_node_t *nft_mxml_build_tree(const char *xml, const char *treename,
				 struct nft_parse_err *err)
{
	mxml_node_t *tree;

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL) {
		err->error = NFT_PARSE_EBADINPUT;
		err->line = 0;
		err->column = 0;
		goto err;
	}

	if (strcmp(tree->value.opaque, treename) == 0)
		return tree;

	mxmlDelete(tree);
err:
	errno = EINVAL;
	return NULL;
}

struct nft_rule_expr *nft_mxml_expr_parse(mxml_node_t *node,
					  struct nft_parse_err *err)
{
	mxml_node_t *tree;
	struct nft_rule_expr *e;
	const char *expr_name;
	char *xml_text;
	int ret;

	expr_name = mxmlElementGetAttr(node, "type");
	if (expr_name == NULL) {
		err->node_name = "type";
		err->error = NFT_PARSE_EMISSINGNODE;
		goto err;
	}

	e = nft_rule_expr_alloc(expr_name);
	if (e == NULL)
		goto err;

	xml_text = mxmlSaveAllocString(node, MXML_NO_CALLBACK);
	if (xml_text == NULL)
		goto err_expr;

	tree = mxmlLoadString(NULL, xml_text, MXML_OPAQUE_CALLBACK);
	xfree(xml_text);

	if (tree == NULL)
		goto err_expr;

	ret = e->ops->xml_parse(e, tree, err);
	mxmlDelete(tree);

	return ret < 0 ? NULL : e;
err_expr:
	nft_rule_expr_free(e);
err:
	mxmlDelete(tree);
	errno = EINVAL;
	return NULL;
}

int nft_mxml_reg_parse(mxml_node_t *tree, const char *reg_name, uint32_t flags,
		       struct nft_parse_err *err)
{
	mxml_node_t *node;
	uint64_t val;

	node = mxmlFindElement(tree, tree, reg_name, NULL, NULL, flags);
	if (node == NULL) {
		err->error = NFT_PARSE_EMISSINGNODE;
		errno = EINVAL;
		goto err;
	}

	if (nft_strtoi(node->child->value.opaque, BASE_DEC, &val,
		       NFT_TYPE_U64) != 0) {
		err->error = NFT_PARSE_EBADTYPE;
		goto err;
	}

	if (val > NFT_REG_MAX) {
		errno = ERANGE;
		goto err;
	}
	return val;
err:
	err->node_name = reg_name;
	return -1;
}

int nft_mxml_data_reg_parse(mxml_node_t *tree, const char *node_name,
			    union nft_data_reg *data_reg, uint16_t flags,
			    struct nft_parse_err *err)
{
	mxml_node_t *node;

	node = mxmlFindElement(tree, tree, node_name, NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL || node->child == NULL) {
		if (!(flags & NFT_XML_OPT)) {
			err->error = NFT_PARSE_EMISSINGNODE;
			err->node_name = node_name;
			errno = EINVAL;
		}

		return DATA_NONE;
	}

	return nft_data_reg_xml_parse(data_reg, node, err);
}

int
nft_mxml_num_parse(mxml_node_t *tree, const char *node_name,
		   uint32_t mxml_flags, int base, void *number,
		   enum nft_type type, uint16_t flags,
		   struct nft_parse_err *err)
{
	mxml_node_t *node = NULL;
	int ret;

	node = mxmlFindElement(tree, tree, node_name, NULL, NULL, mxml_flags);
	if (node == NULL || node->child == NULL) {
		if (!(flags & NFT_XML_OPT)) {
			errno = EINVAL;
			err->node_name = node_name;
			err->error = NFT_PARSE_EMISSINGNODE;
		}
		return -1;
	}

	ret = nft_strtoi(node->child->value.opaque, base, number, type);

	if (ret != 0) {
		err->error = NFT_PARSE_EBADTYPE;
		err->node_name = node_name;
	}
	return ret;
}

const char *nft_mxml_str_parse(mxml_node_t *tree, const char *node_name,
			       uint32_t mxml_flags, uint16_t flags,
			       struct nft_parse_err *err)
{
	mxml_node_t *node;
	const char *ret;

	node = mxmlFindElement(tree, tree, node_name, NULL, NULL, mxml_flags);
	if (node == NULL || node->child == NULL) {
		if (!(flags & NFT_XML_OPT)) {
			errno = EINVAL;
			err->node_name = node_name;
			err->error = NFT_PARSE_EMISSINGNODE;
		}
		return NULL;
	}

	ret = node->child->value.opaque;
	if (ret == NULL) {
		err->node_name = node_name;
		err->error = NFT_PARSE_EBADTYPE;
	}
	return ret;
}

int nft_mxml_family_parse(mxml_node_t *tree, const char *node_name,
			  uint32_t mxml_flags, uint16_t flags,
			  struct nft_parse_err *err)
{
	const char *family_str;
	int family;

	family_str = nft_mxml_str_parse(tree, node_name, mxml_flags,
					flags, err);
	if (family_str == NULL)
		return -1;

	family = nft_str2family(family_str);
	if (family < 0) {
		err->node_name = node_name;
		errno = EAFNOSUPPORT;
	}

	return family;
}
#endif
