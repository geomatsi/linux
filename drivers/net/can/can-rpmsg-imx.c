// SPDX-License-Identifier: GPL-2.0-only
/*
 * FlexCAN rpmsg driver driver
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>
#include <linux/errno.h>
#include <linux/timekeeping.h>
#include <linux/netdevice.h>
#include <linux/can/dev.h>
#include <linux/can.h>

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

struct can_rpmsg_hub {
	struct rpmsg_device *rpdev;
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
				     struct sk_buff *skb_cmd,
				     struct sk_buff *skb_resp,
				     size_t resp_size)
{
	struct rpmsg_device *rpdev = hub->rpdev;
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_rsp *cmd_rsp;
	struct can_rpmsg_cmd *cmd;

	cmd_rsp = (struct can_rpmsg_rsp *)skb_resp->data;
	cmd = (struct can_rpmsg_cmd *)skb_cmd->data;

	if (le16_to_cpu(cmd_rsp->id) != le16_to_cpu(cmd->id)) {
		dev_warn(dev, "CMD 0x%x: bad cmd ID in response: 0x%x\n",
			 le16_to_cpu(cmd->id), le16_to_cpu(cmd_rsp->id));
		return -EINVAL;
	}

	if (unlikely(le16_to_cpu(cmd_rsp->hdr.len) < resp_size)) {
		dev_warn(dev, "CMD 0x%x: bad response size %u < %zu\n",
			 le16_to_cpu(cmd->id), le16_to_cpu(cmd_rsp->hdr.len),
			 resp_size);
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

	ret = rpmsg_send(rpdev->ept, skb_cmd->data, skb_cmd->len);
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

	ret = can_rpmsg_cmd_check_reply(hub, skb_cmd, response, size_rsp);
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
 * - dst: general remote addr
 * - dst + index + 1: per-device addr
 */
static inline int net2addr(struct net_device *ndev)
{
	struct can_rpmsg_netdev_priv *priv = netdev_priv(ndev);
	struct can_rpmsg_hub *hub = priv->hub;
	int index = priv->index;

	return (hub->rpdev->dst + index + 1);
}

static inline struct net_device *addr2net(struct can_rpmsg_hub *hub, int addr)
{
	int index = addr - hub->rpdev->dst - 1;

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

	/* fw: src + 0: control path */

	if (src == hub->rpdev->dst) {
		skb = __dev_alloc_skb(len, GFP_KERNEL);
		if (unlikely(!skb)) {
			dev_err(dev, "failed to allocate ctrl skb\n");
			return -ENOMEM;
		}

		memcpy(skb_put(skb, len), data, len);
		can_rpmsg_rx_ctrl_handler(hub, skb);
		return 0;
	}

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
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&hub->evq)) != NULL) {
		event = (struct can_rpmsg_evt *)skb->data;
		dev_dbg(dev, "processing event 0x%x\n", event->id);
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

	hub->netdev[hub->devnum] = netdev;
	hub->devnum += 1;

	netdev->netdev_ops = &can_rpmsg_netdev_ops;
	SET_NETDEV_DEV(netdev, dev);

	ret = can_rpmsg_cmd_get_cfg(hub, priv->index, &priv->can);
	if (ret) {
		dev_err(dev, "failed to get can%d settings: %d\n",
			hub->devnum, ret);
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
MODULE_DEVICE_TABLE(rpmsg, can_rpmsg_id_table);

static struct rpmsg_driver can_rpmsg_driver = {
	.drv.name	= KBUILD_MODNAME,
	.id_table	= can_rpmsg_id_table,
	.probe		= can_rpmsg_probe,
	.callback	= can_rpmsg_cb,
	.remove		= can_rpmsg_remove,
};
module_rpmsg_driver(can_rpmsg_driver);

MODULE_DESCRIPTION("Remote processor CAN driver");
MODULE_LICENSE("GPL v2");
