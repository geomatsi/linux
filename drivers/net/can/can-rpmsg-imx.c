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

#define RPMSG_CAN_CLOCKS	16000000
#define RPMSG_CAN_MAXDEV	2
#define RPMSG_CAN_TXBUFS	1

#define HANDSHAKE	"TEST"

struct can_rpmsg_hub {
	struct rpmsg_device *rpdev;
	struct net_device *netdev[RPMSG_CAN_MAXDEV];
	struct work_struct tx_wq;
	struct sk_buff_head txq;
	int devnum;
};

struct can_rpmsg_netdev_priv {
	struct can_priv can;
	struct can_rpmsg_hub *hub;
	int is_canfd;
	int index;
};

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

	/* fw assumption: src can be convered to CAN device index */
	dev_dbg(dev, "can frame from src(0x%x): len %d\n", src, len);

	netdev = addr2net(hub, src);
	if (!netdev) {
		dev_err(dev, "invalid frame source: src(0x%x)\n", src);
		return -ENODEV;
	}

	priv = netdev_priv(netdev);
	if (priv->is_canfd)
		skb = alloc_canfd_skb(netdev, &cfd);
	else
		skb = alloc_can_skb(netdev, (struct can_frame **)&cfd);

	if (!skb) {
		dev_err(dev, "alloc_can_skb failed for can %d\n", priv->index);
		netdev->stats.rx_dropped += 1;
		ret = -ENOMEM;
		goto err_recv;
	}

	if (skb->len < len) {
		dev_err(dev, "unexpected frame length: %d instead of %d\n",
			len, skb->len);
		netdev->stats.rx_dropped += 1;
		ret = -EINVAL;
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
		ret = rpmsg_sendto(rpdev->ept, skb->data, skb->len, dst);
		if (ret) {
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

	if (index >= RPMSG_CAN_MAXDEV) {
		dev_err(dev, "vif index is out of range: %d < %d\n",
			index, RPMSG_CAN_MAXDEV);
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
	int ret;

	ret = open_candev(netdev);
	if (ret)
		return ret;

	netif_start_queue(netdev);

	return 0;
}

static int can_rpmsg_netdev_close(struct net_device *netdev)
{
	struct can_rpmsg_netdev_priv *priv = netdev_priv(netdev);
	struct can_rpmsg_hub *hub = priv->hub;

	netif_stop_queue(netdev);
	cancel_work_sync(&hub->tx_wq);
	skb_queue_purge(&hub->txq);
	close_candev(netdev);

	return 0;
}

static const struct net_device_ops can_rpmsg_netdev_ops = {
		.ndo_open = can_rpmsg_netdev_open,
		.ndo_stop = can_rpmsg_netdev_close,
		.ndo_start_xmit = can_rpmsg_netdev_start_xmit,
};

static struct net_device *rpmsg_add_candev(struct can_rpmsg_hub *hub)
{
	struct device *dev = &hub->rpdev->dev;
	struct can_rpmsg_netdev_priv *priv;
	struct net_device *netdev;

	dev_info(dev, "create can device %d", hub->devnum);

	if (hub->devnum >= RPMSG_CAN_MAXDEV) {
		dev_err(dev, "too many CAN devices");
		return ERR_PTR(-E2BIG);
	}

	netdev = alloc_candev(sizeof(*priv), RPMSG_CAN_TXBUFS);
	if (!netdev)
		return ERR_PTR(-ENOMEM);

	priv = netdev_priv(netdev);
	priv->hub = hub;
	priv->index = hub->devnum;

	hub->netdev[hub->devnum] = netdev;
	hub->devnum += 1;

	netdev->netdev_ops = &can_rpmsg_netdev_ops;
	SET_NETDEV_DEV(netdev, dev);

	priv->can.ctrlmode_supported =
		CAN_CTRLMODE_3_SAMPLES | CAN_CTRLMODE_LISTENONLY;
	priv->can.bittiming.bitrate = RPMSG_CAN_CLOCKS;

	return netdev;
}

static int can_rpmsg_probe(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_hub *hub;
	struct net_device *netdev;
	int ret;
	int i;

	dev_info(dev, "new channel: 0x%x -> 0x%x!\n", rpdev->src, rpdev->dst);

	/* fw assumption: advertise rpmsg address to firmware endpoint */
	ret = rpmsg_send(rpdev->ept, HANDSHAKE, strlen(HANDSHAKE));
	if (ret) {
		dev_err(&rpdev->dev, "rpmsg handshake failed: %d\n", ret);
		return -EINVAL;
	}

	hub = devm_kzalloc(dev, sizeof(*hub), GFP_KERNEL);
	if (!hub)
		return -ENOMEM;

	INIT_WORK(&hub->tx_wq, can_rpmsg_tx_work);
	skb_queue_head_init(&hub->txq);
	dev_set_drvdata(dev, hub);
	hub->rpdev = rpdev;

	for (i = 0; i < RPMSG_CAN_MAXDEV; i++) {
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
	for (i = 0; i < RPMSG_CAN_MAXDEV; i++) {
		netdev = hub->netdev[i];
		if (netdev) {
			unregister_candev(netdev);
			free_candev(netdev);
		}
	}

	dev_set_drvdata(dev, NULL);
	kfree(hub);

	return ret;
}

static void can_rpmsg_remove(struct rpmsg_device *rpdev)
{
	struct device *dev = &rpdev->dev;
	struct can_rpmsg_hub *hub = dev_get_drvdata(dev);
	struct net_device *netdev;
	int i;

	dev_info(dev, "can rpmsg driver is removed\n");

	for (i = 0; i < RPMSG_CAN_MAXDEV; i++) {
		netdev = hub->netdev[i];
		if (netdev) {
			unregister_candev(netdev);
			free_candev(netdev);
		}
	}

	dev_set_drvdata(dev, NULL);
	kfree(hub);
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
