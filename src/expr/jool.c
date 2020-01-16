#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

enum nft_jool_attributes {
	NFTA_JOOL_UNSPEC,
	NFTA_JOOL_TYPE,
	NFTA_JOOL_INSTANCE,
	__NFTA_JOOL_MAX,
};

#define NFTA_JOOL_MAX (__NFTA_JOOL_MAX - 1)

struct nftnl_expr_jool {
	const char		*instance;
	uint8_t			type;
};

#define XT_SIIT		(1 << 0)
#define XT_NAT64	(1 << 1)

static int
nftnl_expr_jool_set(struct nftnl_expr *e, uint16_t type,
		    const void *data, uint32_t data_len)
{
	struct nftnl_expr_jool *jool = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_JOOL_TYPE:
		memcpy(&jool->type, data, sizeof(jool->type));
		break;
	case NFTNL_EXPR_JOOL_INSTANCE:
		jool->instance = strdup(data);
		if (!jool->instance)
			return -1;
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_jool_get(const struct nftnl_expr *e, uint16_t type,
		    uint32_t *data_len)
{
	struct nftnl_expr_jool *jool = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_JOOL_TYPE:
		*data_len = sizeof(jool->type);
		return &jool->type;
	case NFTNL_EXPR_JOOL_INSTANCE:
		*data_len = strlen(jool->instance) + 1;
		return jool->instance;
	}
	return NULL;
}

static int
nftnl_expr_jool_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_JOOL_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTNL_EXPR_JOOL_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
			abi_breakage();
		break;
	case NFTNL_EXPR_JOOL_INSTANCE:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_jool_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_jool *jool = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_JOOL_TYPE))
		mnl_attr_put_u8(nlh, NFTA_JOOL_TYPE, jool->type);
	if (e->flags & (1 << NFTNL_EXPR_JOOL_INSTANCE))
		mnl_attr_put_strz(nlh, NFTA_JOOL_INSTANCE, jool->instance);
}

static int
nftnl_expr_jool_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_jool *jool = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_JOOL_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_jool_cb, tb) < 0)
		return -1;

	if (tb[NFTA_JOOL_TYPE]) {
		jool->type = mnl_attr_get_u8(tb[NFTA_JOOL_TYPE]);
		e->flags |= (1 << NFTNL_EXPR_JOOL_TYPE);
	}
	if (tb[NFTA_JOOL_INSTANCE]) {
		jool->instance =
			strdup(mnl_attr_get_str(tb[NFTA_JOOL_INSTANCE]));
		if (!jool->instance)
			return -1;
		e->flags |= (1 << NFTNL_EXPR_JOOL_INSTANCE);
	}

	return 0;
}

static const char *jt2str(uint8_t xt)
{
	switch (xt) {
	case XT_SIIT:
		return "siit";
	case XT_NAT64:
		return "nat64";
	default:
		return "unknown";
	}
}

static int
nftnl_expr_jool_snprintf_default(char *buf, size_t size,
				 const struct nftnl_expr *e)
{
	struct nftnl_expr_jool *jool = nftnl_expr_data(e);
	int ret, remain = size, offset = 0;

	if (nftnl_expr_is_set(e, NFTNL_EXPR_JOOL_TYPE)) {
		ret = snprintf(buf + offset, remain, "type %s ",
			       jt2str(jool->type));
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if (e->flags & (1 << NFTNL_EXPR_JOOL_INSTANCE)) {
		ret = snprintf(buf, size, "instance %s ", jool->instance);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	return offset;
}

static int
nftnl_expr_jool_snprintf(char *buf, size_t len, uint32_t type,
			 uint32_t flags, const struct nftnl_expr *e)
{
	switch(type) {
	case NFTNL_OUTPUT_DEFAULT:
		return nftnl_expr_jool_snprintf_default(buf, len, e);
	case NFTNL_OUTPUT_XML:
	case NFTNL_OUTPUT_JSON:
	default:
		break;
	}
	return -1;
}

static void
nftnl_expr_jool_free(const struct nftnl_expr *e)
{
	struct nftnl_expr_jool *jool = nftnl_expr_data(e);

	xfree(jool->instance);
}

struct expr_ops expr_ops_jool = {
	.name		= "jool",
	.alloc_len	= sizeof(struct nftnl_expr_jool),
	.max_attr	= NFTA_JOOL_MAX,
	.free		= nftnl_expr_jool_free,
	.set		= nftnl_expr_jool_set,
	.get		= nftnl_expr_jool_get,
	.parse		= nftnl_expr_jool_parse,
	.build		= nftnl_expr_jool_build,
	.snprintf	= nftnl_expr_jool_snprintf,
};
