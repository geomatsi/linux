// SPDX-License-Identifier: GPL-2.0-only
/*
 * FlexCAN rpmsg driver driver
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rpmsg.h>

#define MSG		"hello world!"

static int count = 100;
module_param(count, int, 0644);

struct instance_data {
	int rx_count;
};

static int can_rpmsg_cb(struct rpmsg_device *rpdev, void *data, int len,
			void *priv, u32 src)
{
	struct instance_data *idata = dev_get_drvdata(&rpdev->dev);
	int ret;

	dev_info(&rpdev->dev, "incoming msg %d (src: 0x%x)\n",
		 ++idata->rx_count, src);

	print_hex_dump_debug(__func__, DUMP_PREFIX_NONE, 16, 1, data, len,
			     true);

	/* samples should not live forever */
	if (idata->rx_count >= count) {
		dev_info(&rpdev->dev, "goodbye!\n");
		return 0;
	}

	/* send a new message now */
	ret = rpmsg_send(rpdev->ept, MSG, strlen(MSG));
	if (ret)
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);

	return 0;
}

static int can_rpmsg_probe(struct rpmsg_device *rpdev)
{
	int ret;
	struct instance_data *idata;

	dev_info(&rpdev->dev, "new channel: 0x%x -> 0x%x!\n",
					rpdev->src, rpdev->dst);

	idata = devm_kzalloc(&rpdev->dev, sizeof(*idata), GFP_KERNEL);
	if (!idata)
		return -ENOMEM;

	dev_set_drvdata(&rpdev->dev, idata);

	/* send a message to our remote processor */
	ret = rpmsg_send(rpdev->ept, MSG, strlen(MSG));
	if (ret) {
		dev_err(&rpdev->dev, "rpmsg_send failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void can_rpmsg_remove(struct rpmsg_device *rpdev)
{
	dev_info(&rpdev->dev, "can rpmsg driver is removed\n");
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
