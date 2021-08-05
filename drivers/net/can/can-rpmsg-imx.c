// SPDX-License-Identifier: GPL-2.0-only
/*
 * FlexCAN rpmsg driver driver
 *
 */

#include <linux/kernel.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/errno.h>
#include <linux/timekeeping.h>
#include <linux/netdevice.h>
#include <linux/can/dev.h>
#include <linux/can.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>

#include "can-rpmsg-ipc.h"

#define CAN_RPMSG_MAXDEV	10
#define CAN_RPMSG_TXBUFS	1

#define CAN_RPMSG_CMD_TIMEOUT	(1 * HZ)
#define MAX_RPMSG_BUF_SIZE	(512)

struct can_rpmsg_cmd_state {
	struct completion cmd_completion;
	struct sk_buff *skb_rsp;
	u16 seq;
	bool waiting_for_rsp;
	struct mutex cmd_lock; /* command processing lock */
	spinlock_t rsp_lock; /* lock for resp_skb & waiting_for_resp changes */
};

struct imx_oob_cm_ipc;

struct can_rpmsg_hub {
	struct rpmsg_device *rpdev;
	struct imx_oob_cm_ipc *ctrl;
	struct net_device *netdev[CAN_RPMSG_MAXDEV];
	struct work_struct tx_wq;
	struct sk_buff_head txq;
	struct work_struct ev_wq;
	struct sk_buff_head evq;
	struct can_rpmsg_cmd_state curr_cmd;
	int devnum;
};

struct can_rpmsg_netdev_priv {
	struct can_priv can;
	struct can_rpmsg_hub *hub;
	int index;
};

struct imx_oob_cm_ipc {
	struct mbox_client cl;
	struct mbox_chan *tx;
	struct mbox_chan *rx;
	void *mem_req;
	size_t req_size;
	void *mem_rsp;
	size_t rsp_size;
	void *mem_evt;
	size_t evt_size;
	struct can_rpmsg_hub *hub;
	struct device *dev;
};

static struct imx_oob_cm_ipc *oob_ipc_handle;

static int imx_oob_ipc_get_handle(struct imx_oob_cm_ipc **ipc)
{
       if (!oob_ipc_handle)
               return -EPROBE_DEFER;

       *ipc = oob_ipc_handle;

       return 0;
}

static int can_rpmsg_ctrl_send(struct can_rpmsg_hub *hub,
			       struct sk_buff *skb_cmd)
{
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	int ret;
	u32 msg;

	if (skb_cmd->len > hub->ctrl->req_size) {
		dev_err(dev, "cmd is too long: %u > %zu\n",
			skb_cmd->len, hub->ctrl->req_size);
		return -ENOMEM;
	}

	memcpy(hub->ctrl->mem_req, skb_cmd->data, skb_cmd->len);
	msg = can_rpmsg_to_sig(CAN_RPMSG_CTRL_CMD, skb_cmd->len);
	wmb();

	ret = mbox_send_message(hub->ctrl->tx, (void *)&msg);
	if (ret < 0) {
		dev_err(dev, "failed to send signal: %d\n", ret);
		return ret;
	}

	return 0;
}

static struct sk_buff *can_rpmsg_cmd_alloc(u16 cmd_no, size_t cmd_size)
{
	struct can_rpmsg_cmd *cmd;
	struct sk_buff *cmd_skb;

	cmd_skb = __dev_alloc_skb(MAX_RPMSG_BUF_SIZE, GFP_KERNEL);
	if (unlikely(!cmd_skb))
		return NULL;

	skb_put_zero(cmd_skb, cmd_size);

	cmd = (struct can_rpmsg_cmd *)cmd_skb->data;
	cmd->hdr.len = cpu_to_le16(cmd_skb->len);
	cmd->hdr.type = cpu_to_le16(CAN_RPMSG_CTRL_CMD);
	cmd->id = cpu_to_le16(cmd_no);

	return cmd_skb;
}

static int can_rpmsg_cmd_check_reply(struct can_rpmsg_hub *hub,
				     u16 cmd_id,
				     struct sk_buff *skb_resp,
				     size_t resp_size)
{
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_rsp *cmd_rsp;

	cmd_rsp = (struct can_rpmsg_rsp *)skb_resp->data;

	if (le16_to_cpu(cmd_rsp->id) != cmd_id) {
		dev_warn(dev, "CMD 0x%x: bad cmd ID in response: 0x%x\n",
			 cmd_id, le16_to_cpu(cmd_rsp->id));
		return -EINVAL;
	}

	if (unlikely(le16_to_cpu(cmd_rsp->hdr.len) < resp_size)) {
		dev_warn(dev, "CMD 0x%x: bad response size %u < %zu\n",
			 cmd_id, le16_to_cpu(cmd_rsp->hdr.len), resp_size);
		return -ENOSPC;
	}

	return 0;
}

static int can_rpmsg_cmd_send(struct can_rpmsg_hub *hub,
			      struct sk_buff *skb_cmd,
			      struct sk_buff **skb_rsp,
			      size_t size_rsp)
{
	struct can_rpmsg_cmd_state *state = &hub->curr_cmd;
	struct can_rpmsg_cmd *cmd = (void *)skb_cmd->data;
	struct rpmsg_device *rpdev = hub->rpdev;
	u16 cmd_id = le16_to_cpu(cmd->id);
	struct device *dev = &rpdev->dev;
	struct sk_buff *response = NULL;
	bool resp_not_handled = true;
	long status;
	int ret;

	if (unlikely(!skb_rsp)) {
		dev_kfree_skb(skb_cmd);
		return -EFAULT;
	}

	spin_lock(&state->rsp_lock);
	state->seq++;
	cmd->seq = cpu_to_le16(state->seq);
	WARN(state->skb_rsp, "can_rpmsg: response skb not empty\n");
	state->waiting_for_rsp = true;
	spin_unlock(&state->rsp_lock);

	ret = can_rpmsg_ctrl_send(hub, skb_cmd);
	dev_kfree_skb(skb_cmd);

	if (unlikely(ret))
		goto out;

	status = wait_for_completion_interruptible_timeout(
						&state->cmd_completion,
						CAN_RPMSG_CMD_TIMEOUT);

	spin_lock(&state->rsp_lock);
	resp_not_handled = state->waiting_for_rsp;
	response = state->skb_rsp;
	state->skb_rsp = NULL;
	state->waiting_for_rsp = false;
	spin_unlock(&state->rsp_lock);

	if (unlikely(status <= 0)) {
		if (status == 0) {
			ret = -ETIMEDOUT;
			dev_err(dev, "response timeout\n");
		} else {
			ret = -EINTR;
			dev_dbg(dev, "interrupted\n");
		}
	}

	if (WARN_ON(!response || resp_not_handled)) {
		if (response && resp_not_handled)
			dev_kfree_skb(response);

		ret = -EFAULT;
		goto out;
	}

	if (WARN_ON(!response->data)) {
		dev_kfree_skb(response);
		ret = -EFAULT;
		goto out;
	}

	ret = can_rpmsg_cmd_check_reply(hub, cmd_id, response, size_rsp);
	if (ret) {
		dev_kfree_skb(response);
		goto out;
	}

	if (skb_rsp)
		*skb_rsp = response;
	else
		consume_skb(response);

out:

	return ret;
}

static int can_rpmsg_cmd_init(struct can_rpmsg_hub *hub,
			      u16 *devnum, u16 *major, u16 *minor)
{
	struct can_rpmsg_cmd_init_rsp *cmd_rsp;
	struct can_rpmsg_cmd_init *cmd;
	struct sk_buff *skb_rsp = NULL;
	struct sk_buff *skb_cmd;
	int ret = 0;

	skb_cmd = can_rpmsg_cmd_alloc(CAN_RPMSG_CMD_INIT, sizeof(*cmd));
	if (!skb_cmd)
		return -ENOMEM;

	mutex_lock(&hub->curr_cmd.cmd_lock);

	cmd = (struct can_rpmsg_cmd_init *)skb_cmd->data;

	cmd->major = cpu_to_le16(CAN_RPMSG_MAJOR_VER);
	cmd->minor = cpu_to_le16(CAN_RPMSG_MINOR_VER);
	cmd->addr = cpu_to_le16(hub->rpdev->src);

	ret = can_rpmsg_cmd_send(hub, skb_cmd, &skb_rsp, sizeof(*cmd_rsp));
	if (ret)
		goto out;

	cmd_rsp = (struct can_rpmsg_cmd_init_rsp *)skb_rsp->data;
	ret = le16_to_cpu(cmd_rsp->hdr.result);
	if (ret)
		goto out;

	*devnum = le16_to_cpu(cmd_rsp->devnum);
	*major = le16_to_cpu(cmd_rsp->major);
	*minor = le16_to_cpu(cmd_rsp->minor);

out:
	mutex_unlock(&hub->curr_cmd.cmd_lock);
	consume_skb(skb_rsp);

	return ret;
}

static int can_rpmsg_cmd_up(struct can_rpmsg_hub *hub, u32 index)
{
	struct can_rpmsg_rsp *cmd_rsp;
	struct can_rpmsg_cmd_up *cmd;
	struct sk_buff *skb_rsp = NULL;
	struct sk_buff *skb_cmd;
	int ret = 0;

	skb_cmd = can_rpmsg_cmd_alloc(CAN_RPMSG_CMD_UP, sizeof(*cmd));
	if (!skb_cmd)
		return -ENOMEM;

	mutex_lock(&hub->curr_cmd.cmd_lock);

	cmd = (struct can_rpmsg_cmd_up *)skb_cmd->data;

	cmd->index = cpu_to_le32(index);

	ret = can_rpmsg_cmd_send(hub, skb_cmd, &skb_rsp, sizeof(*cmd_rsp));
	if (ret)
		goto out;

	cmd_rsp = (struct can_rpmsg_rsp *)skb_rsp->data;
	ret = le16_to_cpu(cmd_rsp->result);

out:
	mutex_unlock(&hub->curr_cmd.cmd_lock);
	consume_skb(skb_rsp);

	return ret;
}

static int can_rpmsg_cmd_down(struct can_rpmsg_hub *hub, u32 index)
{
	struct can_rpmsg_rsp *cmd_rsp;
	struct can_rpmsg_cmd_down *cmd;
	struct sk_buff *skb_rsp = NULL;
	struct sk_buff *skb_cmd;
	int ret = 0;

	skb_cmd = can_rpmsg_cmd_alloc(CAN_RPMSG_CMD_DOWN, sizeof(*cmd));
	if (!skb_cmd)
		return -ENOMEM;

	mutex_lock(&hub->curr_cmd.cmd_lock);

	cmd = (struct can_rpmsg_cmd_down *)skb_cmd->data;

	cmd->index = cpu_to_le32(index);

	ret = can_rpmsg_cmd_send(hub, skb_cmd, &skb_rsp, sizeof(*cmd_rsp));
	if (ret)
		goto out;

	cmd_rsp = (struct can_rpmsg_rsp *)skb_rsp->data;
	ret = le16_to_cpu(cmd_rsp->result);

out:
	mutex_unlock(&hub->curr_cmd.cmd_lock);
	consume_skb(skb_rsp);

	return ret;
}

static int can_rpmsg_cmd_get_cfg(struct can_rpmsg_hub *hub, u32 index,
				 struct can_priv *can)
{
	struct can_rpmsg_cmd_get_cfg_rsp *cmd_rsp;
	struct can_rpmsg_cmd_get_cfg *cmd;
	struct sk_buff *skb_rsp = NULL;
	struct sk_buff *skb_cmd;
	int ret = 0;

	skb_cmd = can_rpmsg_cmd_alloc(CAN_RPMSG_CMD_GET_CFG, sizeof(*cmd));
	if (!skb_cmd)
		return -ENOMEM;

	mutex_lock(&hub->curr_cmd.cmd_lock);

	cmd = (struct can_rpmsg_cmd_get_cfg *)skb_cmd->data;

	cmd->index = cpu_to_le32(index);

	ret = can_rpmsg_cmd_send(hub, skb_cmd, &skb_rsp, sizeof(*cmd_rsp));
	if (ret)
		goto out;

	cmd_rsp = (struct can_rpmsg_cmd_get_cfg_rsp *)skb_rsp->data;
	ret = le16_to_cpu(cmd_rsp->hdr.result);
	if (ret)
		goto out;

	can->ctrlmode_supported =
		CAN_CTRLMODE_3_SAMPLES | CAN_CTRLMODE_LISTENONLY;
	can->bittiming.bitrate = le32_to_cpu(cmd_rsp->bitrate);

	if (cmd_rsp->canfd) {
		can->data_bittiming.bitrate = le32_to_cpu(cmd_rsp->dbitrate);
		can->ctrlmode_supported |= CAN_CTRLMODE_FD;
	}

out:
	mutex_unlock(&hub->curr_cmd.cmd_lock);
	consume_skb(skb_rsp);

	return ret;
}

/* fw assumption:
 * - dst + index: per-device addr
 */
static inline int net2addr(struct net_device *ndev)
{
	struct can_rpmsg_netdev_priv *priv = netdev_priv(ndev);
	struct can_rpmsg_hub *hub = priv->hub;
	int index = priv->index;

	return (hub->rpdev->dst + index);
}

static inline struct net_device *addr2net(struct can_rpmsg_hub *hub, int addr)
{
	int index = addr - hub->rpdev->dst;

	if (index < 0 || index > hub->devnum)
		return NULL;

	return hub->netdev[index];
}

static void can_rpmsg_cmd_rsp(struct can_rpmsg_hub *hub, struct sk_buff *skb)
{
	struct can_rpmsg_cmd_state *state = &hub->curr_cmd;
	const struct can_rpmsg_rsp *rsp =
		(const struct can_rpmsg_rsp *)skb->data;
	const u16 seq = le16_to_cpu(rsp->seq);
	const u16 id = le16_to_cpu(rsp->id);
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;

	spin_lock(&state->rsp_lock);

	if (unlikely(!state->waiting_for_rsp)) {
		dev_err(dev, "unexpected response: seq %u cmd 0x%x\n", seq, id);
		goto out_err;
	}

	if (unlikely(seq != state->seq)) {
		dev_err(dev, "seq num mismatch: %u != %u\n", seq, state->seq);
		goto out_err;
	}

	state->skb_rsp = skb;
	state->waiting_for_rsp = false;

	spin_unlock(&state->rsp_lock);

	complete(&state->cmd_completion);
	return;

out_err:
	spin_unlock(&state->rsp_lock);
	dev_kfree_skb_any(skb);
}

static int can_rpmsg_rx_ctrl_handler(struct can_rpmsg_hub *hub,
				     struct sk_buff *skb)
{
	const struct can_rpmsg_ctrl_hdr *hdr = (void *)skb->data;
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	int ret = 0;

	if (unlikely(skb->len < sizeof(*hdr))) {
		dev_warn(dev, "packet is too small: %u\n", skb->len);
		dev_kfree_skb_any(skb);
		return -EINVAL;
	}

	if (unlikely(skb->len != le16_to_cpu(hdr->len))) {
		dev_warn(dev, "cmd reply length mismatch: %u != %u\n",
			 skb->len, le16_to_cpu(hdr->len));
		dev_kfree_skb_any(skb);
		return -EFAULT;
	}

	switch (le16_to_cpu(hdr->type)) {
	case CAN_RPMSG_CTRL_RSP:
		if (unlikely(skb->len < sizeof(struct can_rpmsg_rsp))) {
			dev_warn(dev, "cmd reply too short: %u\n", skb->len);
			dev_kfree_skb_any(skb);
			break;
		}

		can_rpmsg_cmd_rsp(hub, skb);
		break;
	case CAN_RPMSG_CTRL_EVT:
		if (unlikely(skb->len < sizeof(struct can_rpmsg_evt))) {
			dev_warn(dev, "event too short: %u\n", skb->len);
			dev_kfree_skb_any(skb);
			break;
		}

		skb_queue_tail(&hub->evq, skb);
		schedule_work(&hub->ev_wq);
		break;
	default:
		dev_warn(dev, "unknown ctrl type: 0x%x\n",
			 le16_to_cpu(hdr->type));
		dev_kfree_skb_any(skb);
		break;
	}

	return ret;
}

static void imx_oob_handle_rx(struct mbox_client *c, void *msg)
{
	struct imx_oob_cm_ipc *ipc = container_of(c, struct imx_oob_cm_ipc, cl);
	struct can_rpmsg_hub *hub = ipc->hub;
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	u32 signal = *(u32 *)msg;
	struct sk_buff *skb;
	size_t len;
	u32 type;
	int ret;
	u32 ack;

	can_rpmsg_from_sig(signal, &type, &len);
	dev_dbg(dev, "ctrl signal: type %u len %zu\n", type, len);

	switch (type) {
	case CAN_RPMSG_CTRL_RSP:
		skb = __dev_alloc_skb(len, GFP_ATOMIC);
		if (unlikely(!skb)) {
			dev_err(dev, "failed to allocate ctrl response skb\n");
			return;
		}

		memcpy(skb_put(skb, len), hub->ctrl->mem_rsp, len);
		can_rpmsg_rx_ctrl_handler(hub, skb);
		break;
	case CAN_RPMSG_CTRL_EVT:
		skb = __dev_alloc_skb(len, GFP_ATOMIC);
		if (unlikely(!skb)) {
			dev_err(dev, "failed to allocate ctrl event skb\n");
			return;
		}

		memcpy(skb_put(skb, len), hub->ctrl->mem_evt, len);
		ack = can_rpmsg_to_sig(CAN_RPMSG_CTRL_ACK, len);
		ret = mbox_send_message(hub->ctrl->tx, (void *)&ack);
		if (ret < 0)
			dev_warn(dev, "failed to send signal: %d\n", ret);
		can_rpmsg_rx_ctrl_handler(hub, skb);
		break;
	default:
		dev_warn(dev, "unknown ctrl type: 0x%x\n", type);
		break;
	}
}

static int can_rpmsg_cb(struct rpmsg_device *rpdev, void *data, int len,
			void *rpmsg_priv, u32 src)
{
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_hub *hub = dev_get_drvdata(dev);
	struct can_rpmsg_netdev_priv *priv;
	struct skb_shared_hwtstamps *skt;
	struct net_device *netdev;
	struct canfd_frame *cfd;
	struct timespec64 ts;
	struct sk_buff *skb;
	int ret = 0;

	dev_dbg(dev, "can frame from src(0x%x): len %d\n", src, len);

	/* fw: src + X: canX data path */

	netdev = addr2net(hub, src);
	if (!netdev) {
		dev_err(dev, "invalid frame source: src(0x%x)\n", src);
		return -ENODEV;
	}

	priv = netdev_priv(netdev);
	switch (len) {
	case CANFD_MTU:
		skb = alloc_canfd_skb(netdev, &cfd);
		break;
	case CAN_MTU:
		skb = alloc_can_skb(netdev, (struct can_frame **)&cfd);
		break;
	default:
		dev_err(dev, "unexpected frame length: %d instead of %d\n",
			len, skb->len);
		netdev->stats.rx_dropped += 1;
		ret = -EINVAL;
		goto err_recv;
	}

	if (!skb) {
		dev_err(dev, "alloc_can_skb failed for can %d\n", priv->index);
		netdev->stats.rx_dropped += 1;
		ret = -ENOMEM;
		goto err_recv;
	}

	/* fw assumption:  data from fw is can_frame or canfd_frame */
	memcpy(cfd, data, len);

	ktime_get_real_ts64(&ts);
	skt = skb_hwtstamps(skb);
	skt->hwtstamp = timespec64_to_ktime(ts);
	skb->tstamp = timespec64_to_ktime(ts);

	netdev->stats.rx_bytes += cfd->len;
	netdev->stats.rx_packets++;

	netif_rx(skb);

	return ret;

err_recv:
	kfree_skb(skb);
	return ret;
}

static void can_rpmsg_event_work(struct work_struct *work)
{
	struct can_rpmsg_hub *hub =
		container_of(work, struct can_rpmsg_hub, ev_wq);
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	const struct can_rpmsg_evt *event;
	struct can_rpmsg_evt_hb *ev_hb;
	struct sk_buff *skb;
	u16 event_id;

	while ((skb = skb_dequeue(&hub->evq)) != NULL) {
		event = (struct can_rpmsg_evt *)skb->data;
		dev_dbg(dev, "processing event 0x%x\n", event->id);
		event_id = le16_to_cpu(event->id);

		switch (event_id) {
		case CAN_RPMSG_EVT_HB:
			ev_hb = (struct can_rpmsg_evt_hb *)event;
			dev_info(dev, "CM4 HB: %u\n", le32_to_cpu(ev_hb->beat));
			break;
		default:
			dev_warn(dev, "unknown event type: %u\n", event_id);
			break;
		}

		dev_kfree_skb_any(skb);
	}
}

static void can_rpmsg_tx_work(struct work_struct *work)
{
	struct can_rpmsg_hub *hub =
		container_of(work, struct can_rpmsg_hub, tx_wq);
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	struct sk_buff *skb;
	u32 dst;
	int ret;

	while ((skb = skb_dequeue(&hub->txq)) != NULL) {
		dst = net2addr(skb->dev);
		ret = rpmsg_trysendto(rpdev->ept, skb->data, skb->len, dst);
		if (ret) {
			if (ret == -ENOMEM) {
				queue_work(system_highpri_wq, &hub->tx_wq);
				skb_queue_head(&hub->txq, skb);
				break;
			}

			dev_err(dev, "failed to send frame to %d: %d\n",
				dst, ret);
			skb->dev->stats.tx_dropped++;
		}

		kfree_skb(skb);
	}
}

static netdev_tx_t can_rpmsg_netdev_start_xmit(struct sk_buff *skb,
					       struct net_device *netdev)
{
	struct can_rpmsg_netdev_priv *priv = netdev_priv(netdev);
	struct can_rpmsg_hub *hub = priv->hub;
	struct device *dev = &hub->rpdev->dev;
	u8 index = priv->index;

	if (can_dropped_invalid_skb(netdev, skb)) {
		dev_err(dev, "Drop invalid can frame\n");
		return NETDEV_TX_OK;
	}

	if (index > hub->devnum) {
		dev_err(dev, "vif index is out of range: %d > %d\n",
			index, hub->devnum);
		netdev->stats.tx_dropped++;
		kfree_skb(skb);
		goto out;
	}

	if (unlikely(skb->dev != netdev)) {
		dev_err(dev, "invalid skb->dev\n");
		netdev->stats.tx_dropped++;
		kfree_skb(skb);
		goto out;
	}

	skb_queue_tail(&hub->txq, skb);
	queue_work(system_highpri_wq, &hub->tx_wq);

out:
	return NETDEV_TX_OK;
}

static int can_rpmsg_netdev_open(struct net_device *netdev)
{
	struct can_rpmsg_netdev_priv *priv = netdev_priv(netdev);
	struct can_rpmsg_hub *hub = priv->hub;
	struct device *dev = &hub->rpdev->dev;
	u32 index = priv->index;
	int ret;

	ret = open_candev(netdev);
	if (ret)
		return ret;

	ret = can_rpmsg_cmd_up(hub, index);
	if (ret) {
		dev_err(dev, "failed to start candev %d: %d\n", index, ret);
		return ret;
	}

	netif_start_queue(netdev);

	return 0;
}

static int can_rpmsg_netdev_close(struct net_device *netdev)
{
	struct can_rpmsg_netdev_priv *priv = netdev_priv(netdev);
	struct can_rpmsg_hub *hub = priv->hub;
	struct device *dev = &hub->rpdev->dev;
	u32 index = priv->index;
	int ret;

	netif_stop_queue(netdev);

	ret = can_rpmsg_cmd_down(hub, index);
	if (ret)
		dev_err(dev, "failed to stop candev %d: %d\n", index, ret);

	close_candev(netdev);

	return ret;
}

static const struct net_device_ops can_rpmsg_netdev_ops = {
		.ndo_open = can_rpmsg_netdev_open,
		.ndo_stop = can_rpmsg_netdev_close,
		.ndo_start_xmit = can_rpmsg_netdev_start_xmit,
		.ndo_change_mtu = can_change_mtu,
};

static struct net_device *rpmsg_add_candev(struct can_rpmsg_hub *hub)
{
	struct device *dev = &hub->rpdev->dev;
	struct can_rpmsg_netdev_priv *priv;
	struct net_device *netdev;
	int ret;

	dev_info(dev, "create can device %d", hub->devnum);

	if (hub->devnum >= CAN_RPMSG_MAXDEV) {
		dev_err(dev, "too many CAN devices");
		return ERR_PTR(-E2BIG);
	}

	netdev = alloc_candev(sizeof(*priv), CAN_RPMSG_TXBUFS);
	if (!netdev)
		return ERR_PTR(-ENOMEM);

	priv = netdev_priv(netdev);
	priv->hub = hub;
	priv->index = hub->devnum;

	hub->netdev[priv->index] = netdev;
	hub->devnum += 1;

	netdev->netdev_ops = &can_rpmsg_netdev_ops;
	SET_NETDEV_DEV(netdev, dev);

	ret = can_rpmsg_cmd_get_cfg(hub, priv->index, &priv->can);
	if (ret) {
		dev_err(dev, "failed to get can%d settings: %d\n",
			priv->index, ret);
		hub->netdev[priv->index] = NULL;
		free_candev(netdev);
		return ERR_PTR(-EINVAL);
	}

	return netdev;
}

static int can_rpmsg_probe(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_hub *hub;
	struct net_device *netdev;
	u16 devnum;
	u16 major;
	u16 minor;
	int ret;
	int i;

	dev_info(dev, "new channel: 0x%x -> 0x%x!\n", rpdev->src, rpdev->dst);

	hub = devm_kzalloc(dev, sizeof(*hub), GFP_KERNEL);
	if (!hub)
		return -ENOMEM;

	ret = imx_oob_ipc_get_handle(&hub->ctrl);
	if (ret)
		return ret;

	hub->ctrl->cl.rx_callback = imx_oob_handle_rx;
	hub->ctrl->hub = hub;

	init_completion(&hub->curr_cmd.cmd_completion);
	spin_lock_init(&hub->curr_cmd.rsp_lock);
	mutex_init(&hub->curr_cmd.cmd_lock);

	hub->curr_cmd.waiting_for_rsp = false;
	hub->curr_cmd.skb_rsp = NULL;
	hub->curr_cmd.seq = 0;

	INIT_WORK(&hub->tx_wq, can_rpmsg_tx_work);
	skb_queue_head_init(&hub->txq);

	INIT_WORK(&hub->ev_wq, can_rpmsg_event_work);
	skb_queue_head_init(&hub->evq);

	dev_set_drvdata(dev, hub);
	hub->rpdev = rpdev;

	ret = can_rpmsg_cmd_init(hub, &devnum, &major, &minor);
	if (ret) {
		dev_err(&rpdev->dev, "failed to init fw: %d\n", ret);
		return -EINVAL;
	}

	if (devnum > CAN_RPMSG_MAXDEV) {
		dev_err(&rpdev->dev, "fw reports too many devices: %d > %d\n",
			devnum, CAN_RPMSG_MAXDEV);
		return -EINVAL;
	}

	if (major != CAN_RPMSG_MAJOR_VER) {
		dev_err(&rpdev->dev, "major version mismatch: drv(%u.%u) != fw(%u.%u)\n",
			CAN_RPMSG_MAJOR_VER, CAN_RPMSG_MINOR_VER, major, minor);
		return -EINVAL;
	}

	if (minor != CAN_RPMSG_MINOR_VER)
		dev_warn(&rpdev->dev, "minor version mismatch: drv(%u.%u) != fw(%u.%u)\n",
			 CAN_RPMSG_MAJOR_VER, CAN_RPMSG_MINOR_VER,
			 major, minor);

	for (i = 0; i < devnum; i++) {
		netdev = rpmsg_add_candev(hub);
		if (IS_ERR(netdev)) {
			dev_err(dev, "Failed to add CAN device: %ld",
				PTR_ERR(netdev));
			ret = PTR_ERR(netdev);
			goto candev_err;
		}

		ret = register_candev(netdev);
		if (ret) {
			dev_err(dev, "Failed to register CAN device: %d", ret);
			goto candev_err;
		}
	}

	return ret;

candev_err:
	for (i = 0; i < hub->devnum; i++) {
		netdev = hub->netdev[i];
		if (netdev) {
			unregister_candev(netdev);
			free_candev(netdev);
		}
	}

	dev_set_drvdata(dev, NULL);

	return ret;
}

static void can_rpmsg_remove(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_hub *hub = dev_get_drvdata(dev);
	struct net_device *netdev;
	int i;

	dev_info(dev, "can rpmsg driver is removed\n");

	for (i = 0; i < hub->devnum; i++) {
		netdev = hub->netdev[i];
		if (netdev) {
			unregister_candev(netdev);
			free_candev(netdev);
		}
	}

	cancel_work_sync(&hub->tx_wq);
	skb_queue_purge(&hub->txq);

	cancel_work_sync(&hub->ev_wq);
	skb_queue_purge(&hub->evq);

	dev_set_drvdata(dev, NULL);
}

static struct rpmsg_device_id can_rpmsg_id_table[] = {
	{ .name	= "can-rpmsg-imx" },
	{ },
};

static struct rpmsg_driver can_rpmsg_driver = {
	.drv.name	= "can_rpmsg",
	.drv.owner	= THIS_MODULE,
	.id_table	= can_rpmsg_id_table,
	.probe		= can_rpmsg_probe,
	.callback	= can_rpmsg_cb,
	.remove		= can_rpmsg_remove,
};

static int plat_can_rpmsg_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct of_phandle_iterator it;
	struct imx_oob_cm_ipc *ipc;
	struct reserved_mem *rmem;
	struct mbox_client *cl;
	int ret = 0;

	ipc = devm_kzalloc(&pdev->dev, sizeof(*ipc), GFP_KERNEL);
	if (!ipc)
		return -ENOMEM;

	ipc->dev = dev;
	dev_set_drvdata(dev, ipc);

	cl = &ipc->cl;

	/* mailbox client configuration */
	cl->dev = dev;
	cl->tx_block = false;
	cl->knows_txdone = true;

	/* postpone rx_callback init */
	cl->rx_callback = NULL;

	/* control path signaling */

	ipc->tx = mbox_request_channel_byname(cl, "ctx");
	if (IS_ERR(ipc->tx)) {
		ret = PTR_ERR(ipc->tx);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to request tx chan: %d\n", ret);
		ipc->tx = NULL;
		goto out;
	}

	ipc->rx = mbox_request_channel_byname(cl, "crx");
	if (IS_ERR(ipc->rx)) {
		ret = PTR_ERR(ipc->rx);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to request rx chan: %d\n", ret);
		ipc->rx = NULL;
		goto out;
	}

	/* control path shared buffers */

	of_phandle_iterator_init(&it, dev->of_node, "memory-region", NULL, 0);
	while (of_phandle_iterator_next(&it) == 0) {
		rmem = of_reserved_mem_lookup(it.node);
		if (!rmem) {
			dev_err(dev, "unable to acquire memory-region\n");
			ret = -EINVAL;
			goto out;
		}

		if (!strcmp(it.node->name, "ctrl_req")) {
			ipc->req_size = rmem->size;
			ipc->mem_req = devm_ioremap_nocache(dev, rmem->base,
							    rmem->size);
			if (!ipc->mem_req) {
				dev_err(dev, "failed to map memory region\n");
				ret = -EBUSY;
				goto out;
			}
		}

		if (!strcmp(it.node->name, "ctrl_rsp")) {
			ipc->rsp_size = rmem->size;
			ipc->mem_rsp = devm_ioremap_nocache(dev, rmem->base,
							    rmem->size);
			if (!ipc->mem_rsp) {
				dev_err(dev, "failed to map memory region\n");
				ret = -EBUSY;
				goto out;
			}
		}

		if (!strcmp(it.node->name, "ctrl_evt")) {
			ipc->evt_size = rmem->size;
			ipc->mem_evt = devm_ioremap_nocache(dev, rmem->base,
							    rmem->size);
			if (!ipc->mem_evt) {
				dev_err(dev, "failed to map memory region\n");
				ret = -EBUSY;
				goto out;
			}
		}
	}

	if (!ipc->mem_req) {
		dev_err(dev, "failed to find 'ctrl_req' memory region\n");
		ret = -ENOMEM;
		goto out;
	}

	if (!ipc->mem_rsp) {
		dev_err(dev, "failed to find 'ctrl_rsp' memory region\n");
		ret = -ENOMEM;
		goto out;
	}

	if (!ipc->mem_evt) {
		dev_err(dev, "failed to find 'ctrl_evt' memory region\n");
		ret = -ENOMEM;
		goto out;
	}

	dev_info(dev, "control path request buffer: start 0x%p size %zu\n",
		 ipc->mem_req, ipc->req_size);
	dev_info(dev, "control path response buffer: start 0x%p size %zu\n",
		 ipc->mem_rsp, ipc->rsp_size);
	dev_info(dev, "control path events buffer: start 0x%p size %zu\n",
		 ipc->mem_evt, ipc->evt_size);
	oob_ipc_handle = ipc;

	ret = register_rpmsg_driver(&can_rpmsg_driver);
	if (ret) {
		dev_err(dev, "failed to register can rpmsg driver: %d\n", ret);
		goto out;
	}

	return 0;
out:
	mbox_free_channel(ipc->tx);
	mbox_free_channel(ipc->rx);

	return ret;
}

static int plat_can_rpmsg_remove(struct platform_device *pdev)
{
	struct imx_oob_cm_ipc *ipc;

	ipc = dev_get_drvdata(&pdev->dev);

	unregister_rpmsg_driver(&can_rpmsg_driver);

	mbox_free_channel(ipc->tx);
	mbox_free_channel(ipc->rx);

	return 0;
}

static const struct of_device_id plat_can_rpmsg_dt_ids[] = {
	{ .compatible = "fsl,plat-can-rpmsg", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, plat_can_rpmsg_dt_ids);

static struct platform_driver plat_can_rpmsg_driver = {
	.driver	= {
		.name	= "plat_can_rpmsg",
		.of_match_table = plat_can_rpmsg_dt_ids,
	},
	.probe	= plat_can_rpmsg_probe,
	.remove	= plat_can_rpmsg_remove,
};
module_platform_driver(plat_can_rpmsg_driver);

MODULE_DESCRIPTION("Remote processor CAN driver");
MODULE_LICENSE("GPL v2");
