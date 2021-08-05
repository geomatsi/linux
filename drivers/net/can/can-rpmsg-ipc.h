/* SPDX-License-Identifier: GPL-2.0-only
 *
 * FlexCAN rpmsg driver driver
 *
 */

#ifndef __CAN_RPMSG_IPC__
#define __CAN_RPMSG_IPC__

#include <linux/kernel.h>
#include <linux/errno.h>

#define CAN_RPMSG_MAJOR_VER	1
#define CAN_RPMSG_MINOR_VER	1

/* control msg header */

struct can_rpmsg_ctrl_hdr {
	__le16 type;
	__le16 len;
} __packed;

/* events */

enum can_rpmsg_evt_type {
	CAN_RPMSG_EVT_HB	= 0x0001,
};

struct can_rpmsg_evt {
	struct can_rpmsg_ctrl_hdr hdr;
	__le16 id;
	u8 rsvd[2];
} __packed;

struct can_rpmsg_evt_hb {
	struct can_rpmsg_evt hdr;
	__le32 beat;
} __packed;

/* commands */

enum can_rpmsg_ctrl_type {
	CAN_RPMSG_CTRL_CMD = 1,
	CAN_RPMSG_CTRL_RSP = 2,
	CAN_RPMSG_CTRL_EVT = 3,
	CAN_RPMSG_CTRL_ACK = 4,
};

enum can_rpmsg_cmd_type {
	CAN_RPMSG_CMD_INIT	= 0x0001,
	CAN_RPMSG_CMD_UP	= 0x0002,
	CAN_RPMSG_CMD_DOWN	= 0x0003,
	CAN_RPMSG_CMD_GET_CFG	= 0x0004,
};

struct can_rpmsg_cmd {
	struct can_rpmsg_ctrl_hdr hdr;
	__le16 id;
	__le16 seq;
} __packed;

struct can_rpmsg_rsp {
	struct can_rpmsg_ctrl_hdr hdr;
	__le16 id;
	__le16 seq;
	__le16 result;
	u8 rsvd[2];
} __packed;

struct can_rpmsg_cmd_init {
	struct can_rpmsg_cmd hdr;
	__le16 major;
	__le16 minor;
	__le16 addr;
} __packed;

struct can_rpmsg_cmd_init_rsp {
	struct can_rpmsg_rsp hdr;
	__le16 major;
	__le16 minor;
	__le16 devnum;
} __packed;

struct can_rpmsg_cmd_up {
	struct can_rpmsg_cmd hdr;
	__le32 index;
} __packed;

struct can_rpmsg_cmd_down {
	struct can_rpmsg_cmd hdr;
	__le32 index;
} __packed;

struct can_rpmsg_cmd_get_cfg {
	struct can_rpmsg_cmd hdr;
	__le32 index;
} __packed;

struct can_rpmsg_cmd_get_cfg_rsp {
	struct can_rpmsg_rsp hdr;
	__le32 index;
	__le32 bitrate;
	__le32 dbitrate;
	__le32 bitrate_mask;
	__le32 dbitrate_mask;
	u8 canfd;
} __packed;

enum can_rpmsg_bitrate {
	CAN_RPMSG_125K		= BIT(0),
	CAN_RPMSG_250K		= BIT(1),
	CAN_RPMSG_500K		= BIT(2),
	CAN_RPMSG_1000K		= BIT(3),
	CAN_RPMSG_2000K		= BIT(4),
	CAN_RPMSG_3000K		= BIT(5),
	CAN_RPMSG_4000K		= BIT(6),
};

/* control path */

static inline u32 can_rpmsg_to_sig(enum can_rpmsg_ctrl_type type, size_t size)
{
	return ((size << 16) | type);
}

static inline void can_rpmsg_from_sig(u32 signal, u32 *type, size_t *size)
{
	*type = signal & 0xffff;
	*size = (signal >> 16) & 0xffff;
}

#endif /* __CAN_RPMSG_IPC__ */
